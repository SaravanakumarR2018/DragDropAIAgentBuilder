import { Users } from "@/types/api";

const parseTrialUntil = (trialUntil?: string): number | null => {
  if (!trialUntil) {
    return null;
  }
  const parsed = new Date(trialUntil);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.getTime();
};

export const resolveHasAccess = (optins?: Users["optins"]): boolean => {
  if (!optins) {
    return false;
  }

  if (typeof optins.has_access === "boolean") {
    return optins.has_access;
  }

  if (optins.skip_trial_access) {
    return true;
  }

  const trialUntil = parseTrialUntil(optins.trial_access_until);
  if (trialUntil === null) {
    return false;
  }

  return trialUntil > Date.now();
};
