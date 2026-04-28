package scheduler

import (
	"certwarden-client/pkg/logger"
	"certwarden-client/pkg/worker"
	"context"
	"errors"
	"math/rand"
	"time"

	"fortio.org/duration"
	"github.com/go-co-op/gocron/v2"
)

type JobManager struct {
	jobs      []*worker.CertJob
	queue     chan *worker.CertJob
	scheduler gocron.Scheduler
	workers   int
	ctx       context.Context
	cancel    context.CancelFunc
}

func retryBackoff(attempt int) time.Duration {
	base := time.Second * time.Duration(1<<attempt)

	if base > time.Minute {
		base = time.Minute
	}

	jitter := time.Duration(rand.Int63n(int64(base / 2)))
	return base + jitter
}

func NewJobManager(jobs []*worker.CertJob, workers int) (*JobManager, error) {
	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &JobManager{
		jobs:      jobs,
		queue:     make(chan *worker.CertJob, len(jobs)),
		scheduler: scheduler,
		workers:   workers,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (m *JobManager) registerSchedule(job *worker.CertJob) {
	_, err := m.scheduler.NewJob(
		gocron.DurationJob(job.RunInterval),
		gocron.NewTask(func() {
			cronJobCtx, cancel := context.WithTimeout(
				context.WithValue(
					m.ctx,
					worker.JobIDContextKey,
					"cron",
				),
				job.JobTimeout,
			)
			defer cancel()

			err := job.Run(cronJobCtx)
			if err != nil {
				logger.Log.Errorf("scheduled job %s failed: %v", job.Name, err)
			}
		}),
	)

	if err != nil {
		logger.Log.Errorf("failed to schedule %s: %v", job.Name, err)
	}
}

func (m *JobManager) executeBootstrap(workerID int, job *worker.CertJob) {
	attempt := 0
	for {
		jobCtx, cancel := context.WithTimeout(context.WithValue(m.ctx, worker.JobIDContextKey, workerID), job.JobTimeout)
		err := job.Run(jobCtx)

		if err == nil {
			logger.Log.Infof("job %s succeeded", job.Name)
			logger.Log.WithField("job", job.Name).WithField("interval", duration.Duration(job.RunInterval).String()).Info("Scheduling job")
			m.registerSchedule(job)
			cancel()
			return
		}

		var wait time.Duration
		if errors.Is(err, context.Canceled) {
			logger.Log.Errorf("Bootstrap job for %s canceled",
				job.Name)
			cancel()
			return
		}
		wait = retryBackoff(attempt)
		attempt++

		logger.Log.Errorf("job %s failed: %v, retrying in %s",
			job.Name, err, wait)

		select {
		case <-m.ctx.Done():
			logger.Log.Errorf("Bootstrap job for %s canceled",
				job.Name)
			cancel()
			return
		case <-time.After(wait):
		}
		cancel()
	}
}

func (m *JobManager) worker(id int) {
	logger.Log.Debugf("Worker %d spawned", id)
	for {
		select {
		case job := <-m.queue:
			logger.Log.Debugf("Worker %d processing job %s", id, job.Name)
			m.executeBootstrap(id, job)
		case <-time.After(10 * time.Second):
			logger.Log.Debugf("Worker %d was blocked for more than 10s, exiting", id)
			return
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *JobManager) Start() {
	for i := 0; i < m.workers; i++ {
		go m.worker(i + 1)
	}
	for _, job := range m.jobs {
		m.queue <- job
	}
	m.scheduler.Start()
}

func (m *JobManager) Stop() {
	m.cancel()
	_ = m.scheduler.Shutdown()
}
