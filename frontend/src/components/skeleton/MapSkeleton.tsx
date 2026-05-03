import { Skeleton } from "@/components/ui/skeleton";

const MapSkeleton = () => {
  return (
    <div className="relative flex flex-1 overflow-hidden rounded-2xl border border-border/60 bg-muted">
      <Skeleton className="absolute inset-0 rounded-none" />
      <div className="absolute inset-x-3 top-3 mx-auto flex max-w-3xl flex-col items-center gap-2">
        <Skeleton className="h-12 w-full max-w-xl rounded-full" />
        <div className="flex max-w-full gap-2 overflow-hidden rounded-full bg-background/70 p-1">
          <Skeleton className="h-8 w-20 rounded-full" />
          <Skeleton className="h-8 w-24 rounded-full" />
          <Skeleton className="h-8 w-28 rounded-full" />
        </div>
      </div>
      <Skeleton className="absolute bottom-5 left-4 hidden h-36 w-72 rounded-2xl lg:block" />
      <Skeleton className="absolute bottom-[calc(env(safe-area-inset-bottom)+1rem)] left-1/2 h-12 w-32 -translate-x-1/2 rounded-full sm:bottom-5" />
      <Skeleton className="absolute bottom-[calc(env(safe-area-inset-bottom)+5.25rem)] right-3 size-12 rounded-full sm:bottom-5 sm:right-4" />
    </div>
  );
};

export default MapSkeleton;
