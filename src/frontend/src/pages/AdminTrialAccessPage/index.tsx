import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { useGetUsers, useUpdateUser } from "@/controllers/API/queries/auth";
import type { Users } from "@/types/api";

const PAGE_SIZE = 25;

function getDaysRemaining(dateValue: string | undefined) {
  if (!dateValue) return null;
  const parsed = new Date(dateValue);
  if (Number.isNaN(parsed.getTime())) return null;
  const diff = parsed.getTime() - Date.now();
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

export default function AdminTrialAccessPage() {
  const [emailSearch, setEmailSearch] = useState("");
  const [searching, setSearching] = useState(false);
  const [saving, setSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [selectedUser, setSelectedUser] = useState<Users | null>(null);
  const [trialDate, setTrialDate] = useState<string>("");
  const [skipTrial, setSkipTrial] = useState(false);

  const { mutateAsync: fetchUsers } = useGetUsers({});
  const { mutateAsync: patchUser } = useUpdateUser({});

  const handlePopulateUser = (user: Users) => {
    setSelectedUser(user);
    const trialAccess = user.optins?.trial_access_until ?? "";
    setTrialDate(trialAccess ? trialAccess.split("T")[0] : "");
    setSkipTrial(Boolean(user.optins?.skip_trial_access));
  };

  const handleSearch = async () => {
    setSearching(true);
    setSaving(false);
    setStatusMessage(null);
    setErrorMessage(null);
    setSelectedUser(null);

    const normalizedEmail = emailSearch.trim().toLowerCase();
    if (!normalizedEmail) {
      setErrorMessage("Please enter an email to search.");
      setSearching(false);
      return;
    }

    let foundUser: Users | null = null;
    let offset = 0;
    let total = Number.POSITIVE_INFINITY;

    try {
      while (offset < total) {
        const response: any = await fetchUsers({
          skip: offset,
          limit: PAGE_SIZE,
        });
        const users: Users[] = response?.users ?? [];
        total = response?.total_count ?? users.length;

        foundUser =
          users.find(
            (user) => user.username?.toLowerCase() === normalizedEmail,
          ) ?? null;

        if (foundUser) {
          handlePopulateUser(foundUser);
          setStatusMessage("User found. You can adjust the trial settings.");
          break;
        }

        if (users.length === 0) break;
        offset += users.length;
      }

      if (!foundUser) {
        setStatusMessage(null);
        setErrorMessage("No user found with that email.");
      }
    } catch (err: any) {
      setErrorMessage(
        err?.response?.data?.detail ??
          "Unable to search users right now. Please try again.",
      );
    } finally {
      setSearching(false);
    }
  };

  const handleUpdateTrial = async () => {
    if (!selectedUser) return;

    const parsed = trialDate ? new Date(trialDate) : null;
    if (parsed && Number.isNaN(parsed.getTime())) {
      setErrorMessage("Please provide a valid trial end date.");
      return;
    }

    setSaving(true);
    setErrorMessage(null);
    setStatusMessage(null);

    try {
      const updateOptins = {
        ...(selectedUser.optins ?? {}),
        ...(parsed ? { trial_access_until: parsed.toISOString() } : {}),
        skip_trial_access: skipTrial,
      };

      await patchUser({
        user_id: selectedUser.id,
        user: { optins: updateOptins },
      });

      const updatedUser = {
        ...selectedUser,
        optins: updateOptins,
      };

      handlePopulateUser(updatedUser);
      setStatusMessage("Trial settings updated.");
    } catch (err: any) {
      setErrorMessage(
        err?.response?.data?.detail ??
          "Unable to update trial settings right now.",
      );
    } finally {
      setSaving(false);
    }
  };

  const daysRemaining = getDaysRemaining(selectedUser?.optins?.trial_access_until);

  return (
    <div className="flex h-full w-full flex-col gap-4 p-6">
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Trial Access</h1>
        <p className="text-sm text-muted-foreground">
          Search for a user by email, review their trial window, and adjust the
          end date or skip flag.
        </p>
      </div>

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>Find a user</CardTitle>
          <CardDescription>
            Search matches the username field, which is typically the user&apos;s email.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:gap-3">
            <div className="flex-1">
              <Label htmlFor="email-search">Email</Label>
              <Input
                id="email-search"
                placeholder="user@example.com"
                value={emailSearch}
                onChange={(event) => setEmailSearch(event.target.value)}
                data-testid="trial-search-input"
              />
            </div>
            <Button
              variant="primary"
              className="w-full sm:w-auto"
              onClick={handleSearch}
              disabled={searching}
              data-testid="trial-search-button"
            >
              {searching ? "Searching..." : "Search"}
            </Button>
          </div>

          {statusMessage ? (
            <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-900 dark:text-emerald-100">
              {statusMessage}
            </div>
          ) : null}
          {errorMessage ? (
            <div className="rounded-md bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-100">
              {errorMessage}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {selectedUser ? (
        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Trial window</span>
              <span className="text-xs text-muted-foreground">
                User ID: {selectedUser.id}
              </span>
            </CardTitle>
            <CardDescription>
              Current email: <strong>{selectedUser.username}</strong>
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="grid gap-3">
              <div className="flex flex-col gap-2">
                <Label htmlFor="trial-end-date">Trial end date</Label>
                <Input
                  id="trial-end-date"
                  type="date"
                  value={trialDate}
                  onChange={(event) => setTrialDate(event.target.value)}
                  data-testid="trial-date-input"
                />
                <p className="text-xs text-muted-foreground">
                  {selectedUser.optins?.trial_access_until
                    ? `Stored value: ${selectedUser.optins.trial_access_until}`
                    : "No trial end date has been set yet."}
                </p>
              </div>

              <Separator />

              <div className="flex items-center justify-between rounded-md border px-3 py-2">
                <div className="flex flex-col">
                  <Label htmlFor="skip-trial-toggle">Skip trial</Label>
                  <p className="text-xs text-muted-foreground">
                    Skip the trial requirement for this user.
                  </p>
                </div>
                <Switch
                  id="skip-trial-toggle"
                  checked={skipTrial}
                  onCheckedChange={(checked) => setSkipTrial(checked)}
                  data-testid="trial-skip-toggle"
                />
              </div>

              <div className="rounded-md bg-muted px-3 py-2 text-sm">
                <p>
                  Days remaining:{" "}
                  {daysRemaining !== null ? daysRemaining : "N/A"}
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  if (selectedUser) handlePopulateUser(selectedUser);
                  setStatusMessage("Values reset to the latest saved data.");
                  setErrorMessage(null);
                }}
              >
                Reset
              </Button>
              <Button
                variant="primary"
                onClick={handleUpdateTrial}
                disabled={saving}
                data-testid="trial-save-button"
              >
                {saving ? "Saving..." : "Save changes"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
