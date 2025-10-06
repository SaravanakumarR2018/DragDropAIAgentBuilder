import { memo, useEffect, useMemo, useRef, useState } from "react";

import IconComponent from "@/components/common/genericIconComponent";
import ShadTooltip from "@/components/common/shadTooltipComponent";
import FlowSettingsComponent from "@/components/core/flowSettingsComponent";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { SAVED_HOVER } from "@/constants/constants";
import { useGetRefreshFlowsQuery } from "@/controllers/API/queries/flows/use-get-refresh-flows-query";
import { useGetFoldersQuery } from "@/controllers/API/queries/folders/use-get-folders";
import { useCustomNavigate } from "@/customization/hooks/use-custom-navigate";
import useSaveFlow from "@/hooks/flows/use-save-flow";
import { useUnsavedChanges } from "@/hooks/use-unsaved-changes";
import useAlertStore from "@/stores/alertStore";
import useFlowsManagerStore from "@/stores/flowsManagerStore";
import useFlowStore from "@/stores/flowStore";
import { useShortcutsStore } from "@/stores/shortcuts";
import { swatchColors } from "@/utils/styleUtils";
import { cn, getNumberFromString } from "@/utils/utils";
import { useHotkeys } from "react-hotkeys-hook";
import { useShallow } from "zustand/react/shallow";

export const MenuBar = memo((): JSX.Element => {
  const setSuccessData = useAlertStore((state) => state.setSuccessData);
  const saveLoading = useFlowsManagerStore((state) => state.saveLoading);
  const [openSettings, setOpenSettings] = useState(false);
  const navigate = useCustomNavigate();
  const isBuilding = useFlowStore((state) => state.isBuilding);
  const saveFlow = useSaveFlow();
  const autoSaving = useFlowsManagerStore((state) => state.autoSaving);
  const {
    currentFlowName,
    currentFlowId,
    currentFlowFolderId,
    currentFlowIcon,
    currentFlowGradient,
  } = useFlowStore(
    useShallow((state) => ({
      currentFlowName: state.currentFlow?.name,
      currentFlowId: state.currentFlow?.id,
      currentFlowFolderId: state.currentFlow?.folder_id,
      currentFlowIcon: state.currentFlow?.icon,
      currentFlowGradient: state.currentFlow?.gradient,
    })),
  );
  const { updated_at: updatedAt } = useFlowsManagerStore(
    useShallow((state) => ({
      updated_at: state.currentFlow?.updated_at,
    })),
  );
  const onFlowPage = useFlowStore((state) => state.onFlowPage);
  const flowTitleContainerRef = useRef<HTMLDivElement>(null);
  const [flowTitleMode, setFlowTitleMode] = useState<"full" | "compact" | "icon">(
    "full",
  );
  const changesNotSaved = useUnsavedChanges();

  const { data: folders, isFetched: isFoldersFetched } = useGetFoldersQuery();

  useGetRefreshFlowsQuery(
    {
      get_all: true,
      header_flows: true,
    },
    { enabled: isFoldersFetched },
  );

  const currentFolder = useMemo(
    () => folders?.find((f) => f.id === currentFlowFolderId),
    [folders, currentFlowFolderId],
  );

  const handleSave = () => {
    saveFlow().then(() => {
      setSuccessData({ title: "Saved successfully" });
    });
  };

  useEffect(() => {
    if (typeof ResizeObserver === "undefined") {
      return;
    }

    const element = flowTitleContainerRef.current;
    if (!element) {
      return;
    }

    const pickMode = (width: number) => {
      if (width < 88) {
        return "icon" as const;
      }
      if (width < 148) {
        return "compact" as const;
      }
      return "full" as const;
    };

    const updateMode = (width: number) => {
      setFlowTitleMode((prev) => {
        const next = pickMode(width);
        return prev === next ? prev : next;
      });
    };

    updateMode(element.getBoundingClientRect().width);

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) {
        return;
      }
      updateMode(entry.contentRect.width);
    });

    observer.observe(element);

    return () => {
      observer.disconnect();
    };
  }, []);

  const flowName = useMemo(() => {
    const name = currentFlowName?.trim();
    return name && name.length > 0 ? name : "Untitled Flow";
  }, [currentFlowName]);

  const compactFlowLabel = useMemo(() => {
    const normalized = flowName.replace(/\s+/g, "");
    if (!normalized) {
      return "";
    }
    return normalized.slice(0, 2).toUpperCase();
  }, [flowName]);

  const flowTitleAssistiveLabel = flowTitleMode === "full" ? undefined : flowName;

  const changes = useShortcutsStore((state) => state.changesSave);
  useHotkeys(changes, handleSave, { preventDefault: true });

  const swatchIndex =
    (currentFlowGradient && !isNaN(parseInt(currentFlowGradient))
      ? parseInt(currentFlowGradient)
      : getNumberFromString(currentFlowGradient ?? currentFlowId ?? "")) %
    swatchColors.length;

  return onFlowPage ? (
    <Popover open={openSettings} onOpenChange={setOpenSettings}>
      <PopoverAnchor>
        <div
          className="relative flex w-full items-center justify-center gap-2 overflow-hidden"
          data-testid="menu_bar_wrapper"
        >
          <div
            className="header-menu-bar hidden max-w-40 justify-end truncate md:flex xl:max-w-full"
            data-testid="menu_flow_bar"
            id="menu_flow_bar_navigation"
          >
            {currentFolder?.name && (
              <div className="hidden truncate md:flex">
                <div
                  className="cursor-pointer truncate text-sm text-muted-foreground hover:text-primary"
                  onClick={() => {
                    navigate(
                      currentFolder?.id
                        ? "/all/folder/" + currentFolder.id
                        : "/all",
                    );
                  }}
                >
                  {currentFolder?.name}
                </div>
              </div>
            )}
          </div>
          <div
            className="hidden w-fit shrink-0 select-none font-normal text-muted-foreground md:flex"
            data-testid="menu_bar_separator"
          >
            /
          </div>
          <div className={cn(`flex rounded p-1`, swatchColors[swatchIndex])}>
            <IconComponent
              name={currentFlowIcon ?? "Workflow"}
              className="h-3.5 w-3.5"
            />
          </div>
          <PopoverTrigger asChild>
            <div
              ref={flowTitleContainerRef}
              className="group relative flex min-w-0 max-w-full cursor-pointer items-center text-sm sm:whitespace-normal"
              data-testid="menu_bar_display"
              aria-label={flowTitleAssistiveLabel}
              title={flowTitleAssistiveLabel}
            >
              <span
                className={cn(
                  "block min-w-0 max-w-full truncate whitespace-pre text-mmd font-semibold sm:text-sm",
                  flowTitleMode !== "full" && "sr-only",
                )}
                data-testid="flow_name"
              >
                {flowName}
              </span>
              {flowTitleMode === "compact" && (
                <span
                  aria-hidden="true"
                  className="text-sm font-semibold uppercase tracking-wide"
                >
                  {compactFlowLabel}
                </span>
              )}

              <IconComponent
                name="pencil"
                className={cn(
                  "pointer-events-none absolute right-0 top-1/2 h-5 w-3.5 -translate-y-1/2 opacity-0 transition-opacity",
                  !openSettings && "sm:group-hover:opacity-100",
                )}
              />
              <span aria-hidden="true" className="w-5 shrink-0" />
            </div>
          </PopoverTrigger>
          <div className={"ml-5 hidden shrink-0 items-center sm:flex"}>
            {!autoSaving && (
              <ShadTooltip
                content={
                  changesNotSaved
                    ? saveLoading
                      ? "Saving..."
                      : "Save Changes"
                    : SAVED_HOVER +
                      (updatedAt
                        ? new Date(updatedAt).toLocaleString("en-US", {
                            hour: "numeric",
                            minute: "numeric",
                          })
                        : "Never")
                }
                side="bottom"
                styleClasses="cursor-default z-10"
              >
                <div>
                  <Button
                    variant="primary"
                    size="iconMd"
                    disabled={!changesNotSaved || isBuilding || saveLoading}
                    className={cn("h-7 w-7 border-border")}
                    onClick={handleSave}
                    data-testid="save-flow-button"
                  >
                    <IconComponent
                      name={saveLoading ? "Loader2" : "Save"}
                      className={cn("h-5 w-5", saveLoading && "animate-spin")}
                    />
                  </Button>
                </div>
              </ShadTooltip>
            )}
          </div>
        </div>
      </PopoverAnchor>
      <PopoverContent
        className="flex w-96 flex-col gap-4 p-4"
        align="center"
        sideOffset={15}
      >
        <span className="text-sm font-semibold">Flow Details</span>
        <FlowSettingsComponent close={() => setOpenSettings(false)} />
      </PopoverContent>
    </Popover>
  ) : (
    <></>
  );
});

export default MenuBar;
