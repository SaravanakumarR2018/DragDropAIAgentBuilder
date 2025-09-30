import { useEffect, useMemo, useState } from "react";

import LoadingComponent from "@/components/common/loadingComponent";
import { cn } from "@/utils/utils";

type Step = {
  label: string;
  completed: boolean;
};

type AppBootstrapLoaderProps = {
  active: boolean;
  overlay?: boolean;
  isAuthComplete: boolean;
  isPreferencesComplete: boolean;
  isExamplesComplete: boolean;
};

const clampProgress = (value: number) => {
  if (Number.isNaN(value)) {
    return 0;
  }

  if (value > 100) {
    return 100;
  }

  if (value < 0) {
    return 0;
  }

  return Math.round(value);
};

export function AppBootstrapLoader({
  active,
  overlay = true,
  isAuthComplete,
  isPreferencesComplete,
  isExamplesComplete,
}: AppBootstrapLoaderProps) {
  const steps = useMemo<Step[]>(
    () => [
      { label: "Authenticating your account", completed: isAuthComplete },
      { label: "Loading workspace preferences", completed: isPreferencesComplete },
      { label: "Fetching starter flows", completed: isExamplesComplete },
    ],
    [isAuthComplete, isPreferencesComplete, isExamplesComplete],
  );

  const computedProgress = useMemo(() => {
    const completedSteps = steps.filter((step) => step.completed).length;

    return clampProgress((completedSteps / steps.length) * 100);
  }, [steps]);

  const [displayProgress, setDisplayProgress] = useState(computedProgress);

  useEffect(() => {
    setDisplayProgress((prev) => {
      if (computedProgress < prev) {
        return prev;
      }

      return computedProgress;
    });
  }, [computedProgress]);

  const activeStep = useMemo(() => steps.find((step) => !step.completed), [steps]);

  const progressValue = clampProgress(displayProgress);

  if (!active) {
    return null;
  }

  return (
    <div
      className={cn(
        "flex h-screen w-screen items-center justify-center bg-background/80 p-6",
        overlay && "fixed left-0 top-0 z-[999] backdrop-blur",
      )}
    >
      <div className="flex w-full max-w-xl flex-col items-center gap-6 rounded-2xl bg-card p-10 shadow-2xl shadow-black/10">
        <LoadingComponent remSize={12} />
        <div className="flex w-full flex-col gap-2">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>{activeStep?.label ?? "Preparing your workspace"}</span>
            <span className="font-medium text-foreground">{progressValue}%</span>
          </div>
          <div
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={progressValue}
            role="progressbar"
            className="h-2 w-full overflow-hidden rounded-full bg-muted"
          >
            <div
              className="h-full rounded-full bg-primary transition-all duration-500 ease-out"
              style={{ width: `${progressValue}%` }}
            />
          </div>
        </div>
        <ul className="grid w-full gap-2 text-sm text-muted-foreground">
          {steps.map((step) => (
            <li
              key={step.label}
              className={cn(
                "flex items-center justify-between rounded-lg border border-transparent bg-muted/40 px-4 py-2",
                step.completed && "border-primary/40 bg-primary/10 text-foreground",
              )}
            >
              <span>{step.label}</span>
              <span
                aria-hidden
                className={cn(
                  "h-2 w-2 rounded-full",
                  step.completed ? "bg-primary" : "bg-muted-foreground",
                )}
              />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
