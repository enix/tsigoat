package cmd

import (
	"fmt"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"go.uber.org/automaxprocs/maxprocs"
)

func (s *ServerSettings) InitRuntime() error {
	if s.UseAutoMaxProcs {
		if err := autoMaxProcs(s); err != nil {
			return fmt.Errorf("automaxprocs: %w", err)
		}
	}

	if s.UseAutoMemLimit {
		if err := autoMemLimit(s); err != nil {
			return fmt.Errorf("automemlimit: %w", err)
		}
	}

	return nil
}

func autoMaxProcs(settings *ServerSettings) error {
	logger := settings.Logger.Sugar()
	_, err := maxprocs.Set(maxprocs.Logger(logger.Infof))
	return err
}

func autoMemLimit(settings *ServerSettings) error {
	_, err := memlimit.SetGoMemLimitWithOpts(
		memlimit.WithLogger(settings.SlogLogger),
	)
	return err
}
