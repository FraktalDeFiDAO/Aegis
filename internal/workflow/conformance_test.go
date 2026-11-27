package workflow

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestUnsupportedStepsFailInsteadOfInventingResults(t *testing.T) {
	for _, kind := range []StepType{StepTypeCrawl, StepTypeInject, StepTypeExtract} {
		t.Run(string(kind), func(t *testing.T) {
			result, err := NewRunner(&Workflow{Name: "unsupported", Steps: []Step{{ID: "test", Type: kind}}}).Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "failure" || result.Steps[0].Output != nil || result.Steps[0].Error == "" {
				t.Fatalf("false success: %+v", result)
			}
		})
	}
}

func TestContinuedFailureMakesWorkflowPartial(t *testing.T) {
	result, err := NewRunner(&Workflow{Name: "partial", Steps: []Step{{ID: "unsupported", Type: StepTypeExtract, ContinueOn: "always"}, {ID: "next", Type: StepTypeWait}}}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial" || len(result.Steps) != 2 || result.Steps[1].Status != "success" {
		t.Fatalf("wrong partial result: %+v", result)
	}
}

func TestParallelStepsRespectParentDeadlineAndJoinBeforeReturning(t *testing.T) {
	wf := &Workflow{Name: "deadline", Steps: []Step{{ID: "parallel", Type: StepTypeParallel, Timeout: "10ms", Config: StepConfig{ParallelSteps: []Step{{ID: "child", Type: StepTypeWait, Config: StepConfig{Duration: "1s"}}}}}}}
	done := make(chan *WorkflowResult, 1)
	go func() { result, _ := NewRunner(wf).Run(context.Background()); done <- result }()
	select {
	case result := <-done:
		if result.Status != "failure" {
			t.Fatalf("deadline falsely succeeded: %+v", result)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("child ignored parent deadline")
	}
}

func TestParallelLimitAndNestedFailures(t *testing.T) {
	runner := NewRunner(&Workflow{Name: "parallel"})
	runner.ctx = context.Background()
	step := Step{Config: StepConfig{MaxParallel: 1, ParallelSteps: []Step{{ID: "first", Type: StepTypeWait, Config: StepConfig{Duration: "1ms"}}, {ID: "second", Type: StepTypeWait}}}}
	output, err := runner.executeParallel(context.Background(), step)
	if err != nil {
		t.Fatal(err)
	}
	results := output.([]StepResult)
	if results[1].StartTime.Before(results[0].EndTime) {
		t.Fatal("MaxParallel=1 did not serialize children")
	}
	step.Config.ParallelSteps = []Step{{ID: "unsupported", Type: StepTypeInject}}
	if _, err := runner.executeParallel(context.Background(), step); err == nil {
		t.Fatal("nested failure reported as successful parallel step")
	}
}

func TestRunnerSerializesConcurrentRuns(t *testing.T) {
	runner := NewRunner(&Workflow{Name: "shared", Steps: []Step{{ID: "wait", Type: StepTypeWait, Config: StepConfig{Duration: "1ms"}}}})
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := runner.Run(context.Background())
			if err != nil || result.Status != "success" {
				t.Errorf("run: %+v, %v", result, err)
			}
		}()
	}
	wg.Wait()
}
