import { useCallback, useEffect, useMemo, useState } from "react";
import { Loader2, RefreshCcw } from "lucide-react";

import { crashComponentPropsType } from "../../../types/components";
import { Button } from "../../ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "../../ui/card";

const DEFAULT_REFRESH_INTERVAL_SECONDS = 60;
const REFRESH_INTERVAL_SECONDS = (() => {
  const configured = Number.parseInt(
    import.meta.env.VITE_UPDATE_SCREEN_REFRESH_INTERVAL ?? `${DEFAULT_REFRESH_INTERVAL_SECONDS}`,
    10,
  );

  return Number.isFinite(configured) && configured > 0
    ? configured
    : DEFAULT_REFRESH_INTERVAL_SECONDS;
})();

export default function UpdateInProgressScreen({
  resetErrorBoundary,
}: crashComponentPropsType): JSX.Element {
  const [secondsRemaining, setSecondsRemaining] = useState(REFRESH_INTERVAL_SECONDS);

  const handleRetry = useCallback(() => {
    setSecondsRemaining(REFRESH_INTERVAL_SECONDS);
    resetErrorBoundary();
  }, [resetErrorBoundary]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setSecondsRemaining((previous) => (previous > 0 ? previous - 1 : 0));
    }, 1000);

    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    if (secondsRemaining === 0) {
      handleRetry();
    }
  }, [handleRetry, secondsRemaining]);

  const formattedTime = useMemo(() => {
    const minutes = Math.floor(secondsRemaining / 60);
    const seconds = secondsRemaining % 60;

    return `${minutes}:${seconds.toString().padStart(2, "0")}`;
  }, [secondsRemaining]);

  const progress = useMemo(() => {
    const completion = ((REFRESH_INTERVAL_SECONDS - secondsRemaining) / REFRESH_INTERVAL_SECONDS) * 100;

    return Math.min(100, Math.max(0, completion));
  }, [secondsRemaining]);

  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-hidden bg-background text-foreground transition-colors">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-32 top-1/4 h-72 w-72 animate-pulse rounded-full bg-primary/20 blur-3xl" />
        <div className="absolute -right-20 bottom-1/4 h-64 w-64 animate-pulse rounded-full bg-muted/60 blur-3xl dark:bg-muted/40" />
      </div>

      <Card className="relative z-10 w-[min(90vw,36rem)] animate-in fade-in-50 border-border/60 bg-background/95 shadow-2xl shadow-primary/10 duration-300 backdrop-blur">
        <CardHeader className="space-y-4 text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-primary/40 bg-primary/10 text-primary">
            <Loader2 className="h-8 w-8 animate-spin" strokeWidth={1.5} />
          </div>

          <div className="space-y-2">
            <h1 className="text-2xl font-semibold">Update in progress</h1>
            <p className="text-sm text-muted-foreground">
              We&apos;re setting up the next version of Langflow for you. Hang tight while we finish the update.
            </p>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              This page will reload automatically as soon as the update is ready. No action needed on your side.
            </p>
            <div className="rounded-lg border border-dashed border-primary/30 bg-primary/5 p-4 text-sm text-primary">
              <span className="font-medium">Workflow status:</span> preparing assets and migrating data for the next release.
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <span>Automatic refresh in</span>
              <span aria-live="polite" aria-atomic="true" className="text-base text-foreground" role="timer">
                {formattedTime}
              </span>
            </div>
            <div
              aria-valuemax={100}
              aria-valuemin={0}
              aria-valuenow={Math.round(progress)}
              aria-valuetext={`${formattedTime} remaining`}
              role="progressbar"
              className="relative h-2 w-full overflow-hidden rounded-full bg-muted"
            >
              <div
                className="absolute inset-y-0 left-0 h-full rounded-full bg-gradient-to-r from-primary to-primary/60 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            We&apos;ll keep trying every minute. If the page doesn&apos;t come back automatically, you can retry the flow manually.
          </p>
        </CardContent>

        <CardFooter className="flex flex-col gap-3 text-sm sm:flex-row sm:items-center sm:justify-between">
          <Button onClick={handleRetry} className="w-full sm:w-auto">
            <RefreshCcw className="mr-2 h-4 w-4" strokeWidth={1.5} />
            Retry now
          </Button>
          <span className="text-xs text-muted-foreground">
            Langflow will refresh on its own. This link is here just in case you need it sooner.
          </span>
        </CardFooter>
      </Card>
    </div>
  );
}
