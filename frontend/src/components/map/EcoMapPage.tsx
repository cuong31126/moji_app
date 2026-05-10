import "leaflet/dist/leaflet.css";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import L from "leaflet";
import {
  MapContainer,
  Marker,
  TileLayer,
  useMap,
  useMapEvents,
} from "react-leaflet";
import {
  ArrowLeft,
  CheckCircle2,
  Crosshair,
  ImagePlus,
  Layers,
  Loader2,
  MapPin,
  MessageCircle,
  Navigation,
  Search,
  Send,
  Share2,
  SlidersHorizontal,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { reportService } from "@/services/reportService";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { useSocketStore } from "@/stores/useSocketStore";
import type {
  TrashReport,
  TrashReportStatus,
  TrashSeverity,
  TrashType,
} from "@/types/report";
import type { Conversation } from "@/types/chat";
import type { User } from "@/types/user";

interface LatLngPoint {
  lat: number;
  lng: number;
}

interface SearchResult {
  place_id: number;
  display_name: string;
  lat: string;
  lon: string;
}

interface FlyTarget extends LatLngPoint {
  zoom: number;
}

type MapMode = "view" | "reporting";
type MapStyle = "street" | "light";

const DEFAULT_CENTER: LatLngPoint = {
  lat: 10.8505,
  lng: 106.7717,
};
const REPORT_LIMIT = 80;
const REPORT_MAX_DISTANCE_METERS = 50000;
const CLEANED_REPORT_RETENTION_MS = 10 * 24 * 60 * 60 * 1000;

const STATUS_META: Record<
  TrashReportStatus,
  { label: string; markerClass: string; badgeClass: string }
> = {
  ACTIVE: {
    label: "Mới báo",
    markerClass: "eco-marker-active",
    badgeClass: "border-red-200 bg-red-50 text-red-700",
  },
  VERIFIED: {
    label: "Đã xác nhận",
    markerClass: "eco-marker-verified",
    badgeClass: "border-orange-200 bg-orange-50 text-orange-700",
  },
  CLEANUP_PENDING: {
    label: "Đang dọn",
    markerClass: "eco-marker-pending",
    badgeClass: "border-sky-200 bg-sky-50 text-sky-700",
  },
  CLEANED: {
    label: "Đã sạch",
    markerClass: "eco-marker-cleaned",
    badgeClass: "border-emerald-200 bg-emerald-50 text-emerald-700",
  },
};

const TYPE_LABELS: Record<TrashType, string> = {
  plastic: "Nhựa",
  organic: "Hữu cơ",
  metal: "Kim loại",
  glass: "Thủy tinh",
  other: "Khác",
};

const SEVERITY_LABELS: Record<TrashSeverity, string> = {
  low: "Nhẹ",
  medium: "Vừa",
  high: "Nặng",
};

const FILTERS: Array<{ value: TrashReportStatus | "ALL"; label: string }> = [
  { value: "ALL", label: "Tất cả" },
  { value: "ACTIVE", label: "Mới báo" },
  { value: "VERIFIED", label: "Đã xác nhận" },
  { value: "CLEANUP_PENDING", label: "Đang dọn" },
  { value: "CLEANED", label: "Đã sạch" },
];

const TILE_LAYERS: Record<MapStyle, { url: string; attribution: string }> = {
  street: {
    url: "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>',
  },
  light: {
    url: "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
    attribution:
      '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
  },
};

const createMarkerIcon = (markerClass: string) =>
  L.divIcon({
    className: "eco-marker-shell",
    html: `<div class="eco-trash-marker ${markerClass}"><span></span></div>`,
    iconSize: [34, 42],
    iconAnchor: [17, 42],
  });

const markerIcons: Record<TrashReportStatus, L.DivIcon> = {
  ACTIVE: createMarkerIcon(STATUS_META.ACTIVE.markerClass),
  VERIFIED: createMarkerIcon(STATUS_META.VERIFIED.markerClass),
  CLEANUP_PENDING: createMarkerIcon(STATUS_META.CLEANUP_PENDING.markerClass),
  CLEANED: createMarkerIcon(STATUS_META.CLEANED.markerClass),
};

const userLocationIcon = L.divIcon({
  className: "eco-marker-shell",
  html: '<div class="eco-user-marker"><span></span></div>',
  iconSize: [28, 28],
  iconAnchor: [14, 14],
});

const formatDistance = (meters?: number) => {
  if (meters === undefined) {
    return "";
  }

  if (meters < 1000) {
    return `${meters} m`;
  }

  return `${(meters / 1000).toFixed(1)} km`;
};

const getConversationName = (conversation: Conversation, userId?: string) => {
  if (conversation.type === "group") {
    return conversation.group?.name || "Nhóm chat";
  }

  const otherUser = conversation.participants.find((item) => item._id !== userId);
  return otherUser?.displayName || "Tin nhắn riêng";
};

const getInitials = (name?: string) => {
  return (name || "M")
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
};

const getDistanceMeters = (from: LatLngPoint, to: LatLngPoint) => {
  const earthRadius = 6371000;
  const toRad = (value: number) => (value * Math.PI) / 180;
  const dLat = toRad(to.lat - from.lat);
  const dLng = toRad(to.lng - from.lng);
  const lat1 = toRad(from.lat);
  const lat2 = toRad(to.lat);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) *
      Math.cos(lat2) *
      Math.sin(dLng / 2) *
      Math.sin(dLng / 2);

  return Math.round(earthRadius * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
};

const shouldShowReportOnMap = (report: TrashReport) => {
  const normalizedStatus = report.status.toLowerCase();

  if (
    normalizedStatus !== "cleaned" &&
    normalizedStatus !== "confirmed_clean"
  ) {
    return true;
  }

  const cleanedDate = report.cleanedAt || report.updatedAt;

  if (!cleanedDate) {
    return true;
  }

  return Date.now() - new Date(cleanedDate).getTime() < CLEANED_REPORT_RETENTION_MS;
};

const isAbortError = (error: unknown) => {
  if (error instanceof DOMException && error.name === "AbortError") {
    return true;
  }

  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    (error as { name?: string }).name === "CanceledError"
  );
};

const MapFlyTo = ({ target }: { target: FlyTarget | null }) => {
  const map = useMap();

  useEffect(() => {
    if (!target) {
      return;
    }

    map.flyTo([target.lat, target.lng], target.zoom, {
      duration: 0.9,
    });
  }, [map, target]);

  return null;
};

const MapCenterWatcher = ({
  enabled,
  live,
  onCenterChange,
  onIdleCenterChange,
}: {
  enabled: boolean;
  live?: boolean;
  onCenterChange: (center: LatLngPoint) => void;
  onIdleCenterChange?: (center: LatLngPoint) => void;
}) => {
  const map = useMapEvents({
    move() {
      if (!enabled || !live) {
        return;
      }

      const center = map.getCenter();
      onCenterChange({ lat: center.lat, lng: center.lng });
    },
    moveend() {
      if (!enabled) {
        return;
      }

      const center = map.getCenter();
      const nextCenter = { lat: center.lat, lng: center.lng };
      onCenterChange(nextCenter);
      onIdleCenterChange?.(nextCenter);
    },
  });

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const center = map.getCenter();
    const nextCenter = { lat: center.lat, lng: center.lng };
    onCenterChange(nextCenter);
    onIdleCenterChange?.(nextCenter);
  }, [enabled, map, onCenterChange, onIdleCenterChange]);

  return null;
};

const EcoMapPage = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user } = useAuthStore();
  const {
    conversations,
    addConvo,
    setActiveConversation,
    fetchMessages,
  } = useChatStore();
  const { friends, getFriends, addFriend } = useFriendStore();
  const { socket } = useSocketStore();

  const [reports, setReports] = useState<TrashReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<TrashReport | null>(null);
  const [userLocation, setUserLocation] = useState<LatLngPoint | null>(null);
  const [mapMode, setMapMode] = useState<MapMode>("view");
  const [mapStyle, setMapStyle] = useState<MapStyle>("street");
  const [currentCenter, setCurrentCenter] = useState<LatLngPoint>(DEFAULT_CENTER);
  const [reportQueryCenter, setReportQueryCenter] =
    useState<LatLngPoint>(DEFAULT_CENTER);
  const [draftLocation, setDraftLocation] = useState<LatLngPoint | null>(null);
  const [flyTarget, setFlyTarget] = useState<FlyTarget | null>({
    ...DEFAULT_CENTER,
    zoom: 13,
  });
  const [activeFilter, setActiveFilter] = useState<TrashReportStatus | "ALL">(
    "ALL"
  );
  const [filtersOpen, setFiltersOpen] = useState(true);
  const [loadingReports, setLoadingReports] = useState(false);
  const [initialLocationResolved, setInitialLocationResolved] = useState(false);
  const [locating, setLocating] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [submittingReport, setSubmittingReport] = useState(false);
  const [description, setDescription] = useState("");
  const [trashType, setTrashType] = useState<TrashType>("plastic");
  const [severity, setSeverity] = useState<TrashSeverity>("medium");
  const [reportImages, setReportImages] = useState<File[]>([]);
  const [comments, setComments] = useState<Awaited<
    ReturnType<typeof reportService.fetchComments>
  >>([]);
  const [commentText, setCommentText] = useState("");
  const [loadingComments, setLoadingComments] = useState(false);
  const [commenting, setCommenting] = useState(false);
  const [cleanupOpen, setCleanupOpen] = useState(false);
  const [cleanupDescription, setCleanupDescription] = useState("");
  const [cleanupImages, setCleanupImages] = useState<File[]>([]);
  const [cleaning, setCleaning] = useState(false);
  const [reportActionLoadingById, setReportActionLoadingById] = useState<
    Record<string, boolean>
  >({});
  const [shareOpen, setShareOpen] = useState(false);
  const [shareMode, setShareMode] = useState<"conversation" | "friend">(
    "conversation"
  );
  const [shareConversationId, setShareConversationId] = useState("");
  const [shareFriendId, setShareFriendId] = useState("");
  const [sharing, setSharing] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteFriendIds, setInviteFriendIds] = useState<string[]>([]);
  const [inviting, setInviting] = useState(false);
  const [miniProfileUser, setMiniProfileUser] = useState<User | null>(null);
  const [addingFriend, setAddingFriend] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const handledReportIdRef = useRef<string | null>(null);
  const searchCacheRef = useRef<Record<string, SearchResult[]>>({});
  const searchAbortRef = useRef<AbortController | null>(null);
  const reportFetchCenter = reportQueryCenter;

  const setReportActionLoading = useCallback(
    (reportId: string, isLoading: boolean) => {
      setReportActionLoadingById((prev) => ({
        ...prev,
        [reportId]: isLoading,
      }));
    },
    []
  );

  useEffect(() => {
    return () => {
      searchAbortRef.current?.abort();
    };
  }, []);

  const upsertReport = useCallback((report: TrashReport) => {
    if (!shouldShowReportOnMap(report)) {
      setReports((prev) => prev.filter((item) => item._id !== report._id));
      setSelectedReport((prev) => (prev?._id === report._id ? null : prev));
      return;
    }

    setReports((prev) => {
      const exists = prev.some((item) => item._id === report._id);

      return exists
        ? prev.map((item) =>
            item._id === report._id ? report : item
          )
        : [report, ...prev];
    });

    setSelectedReport((prev) =>
      prev?._id === report._id ? report : prev
    );
  }, []);

  useEffect(() => {
    if (!navigator.geolocation) {
      setInitialLocationResolved(true);
      return;
    }

    let cancelled = false;

    navigator.geolocation.getCurrentPosition(
      (position) => {
        if (cancelled) {
          return;
        }

        const nextLocation = {
          lat: position.coords.latitude,
          lng: position.coords.longitude,
        };

        setUserLocation(nextLocation);
        setCurrentCenter(nextLocation);
        setReportQueryCenter(nextLocation);
        setFlyTarget({ ...nextLocation, zoom: 15 });
        setInitialLocationResolved(true);
      },
      () => {
        if (!cancelled) {
          setInitialLocationResolved(true);
        }
      },
      {
        enableHighAccuracy: false,
        maximumAge: 60000,
        timeout: 7000,
      }
    );

    return () => {
      cancelled = true;
    };
  }, []);

  const loadReports = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoadingReports(true);
      const nextReports = await reportService.fetchReports({
        status: activeFilter,
        lat: reportFetchCenter.lat,
        lng: reportFetchCenter.lng,
        maxDistance: REPORT_MAX_DISTANCE_METERS,
        limit: REPORT_LIMIT,
      }, signal);
      setReports(nextReports.filter(shouldShowReportOnMap));
    } catch (error) {
      if (isAbortError(error)) {
        return;
      }

      console.error(error);
      toast.error("Không tải được danh sách điểm rác");
    } finally {
      if (!signal?.aborted) {
        setLoadingReports(false);
      }
    }
  }, [activeFilter, reportFetchCenter.lat, reportFetchCenter.lng]);

  useEffect(() => {
    if (!initialLocationResolved) {
      return;
    }

    const controller = new AbortController();
    loadReports(controller.signal);

    return () => {
      controller.abort();
    };
  }, [initialLocationResolved, loadReports]);

  const syncReport = useCallback(
    async (reportId: string) => {
      const report = await reportService.fetchReport(reportId);
      upsertReport(report);
      return report;
    },
    [upsertReport]
  );

  useEffect(() => {
    if (!socket) {
      return;
    }

    const handleNewReport = ({ report }: { report: TrashReport }) => {
      upsertReport(report);
    };

    const handleUpdatedReport = ({ report }: { report: TrashReport }) => {
      upsertReport(report);
      if (selectedReport?._id === report._id) {
        syncReport(report._id).catch(console.error);
      }
    };

    const handleCommented = ({ reportId }: { reportId: string }) => {
      if (selectedReport?._id === reportId) {
        Promise.all([
          reportService.fetchComments(reportId),
          syncReport(reportId),
        ])
          .then(([nextComments]) => setComments(nextComments))
          .catch(console.error);
      }
    };

    socket.on("new-trash-report", handleNewReport);
    socket.on("trash-report-updated", handleUpdatedReport);
    socket.on("trash-report-cleaned", handleUpdatedReport);
    socket.on("trash-report-commented", handleCommented);

    return () => {
      socket.off("new-trash-report", handleNewReport);
      socket.off("trash-report-updated", handleUpdatedReport);
      socket.off("trash-report-cleaned", handleUpdatedReport);
      socket.off("trash-report-commented", handleCommented);
    };
  }, [selectedReport?._id, socket, syncReport, upsertReport]);

  useEffect(() => {
    if (!selectedReport || !detailOpen) {
      return;
    }

    let cancelled = false;

    const fetchComments = async () => {
      try {
        setLoadingComments(true);
        const nextComments = await reportService.fetchComments(selectedReport._id);

        if (!cancelled) {
          setComments(nextComments);
        }
      } catch (error) {
        console.error(error);
      } finally {
        if (!cancelled) {
          setLoadingComments(false);
        }
      }
    };

    fetchComments();

    return () => {
      cancelled = true;
    };
  }, [detailOpen, selectedReport]);

  useEffect(() => {
    const reportId = searchParams.get("reportId");

    if (!reportId || handledReportIdRef.current === reportId) {
      return;
    }

    const openReport = async () => {
      try {
        const localReport =
          reports.find((report) => report._id === reportId) ||
          (await reportService.fetchReport(reportId));

        handledReportIdRef.current = reportId;
        setSelectedReport(localReport);
        setDetailOpen(true);
        setFlyTarget({
          lat: localReport.location.lat,
          lng: localReport.location.lng,
          zoom: 17,
        });
      } catch (error) {
        console.error(error);
        toast.error("Không tìm thấy điểm rác được chia sẻ");
      }
    };

    openReport();
  }, [reports, searchParams]);

  useEffect(() => {
    if (shareOpen && conversations.length > 0 && !shareConversationId) {
      setShareConversationId(conversations[0]._id);
    }

    if ((shareOpen || inviteOpen) && friends.length === 0) {
      getFriends();
    }

    if ((shareOpen || inviteOpen) && friends.length > 0 && !shareFriendId) {
      setShareFriendId(friends[0]._id);
    }
  }, [
    conversations,
    friends,
    getFriends,
    inviteOpen,
    shareConversationId,
    shareFriendId,
    shareOpen,
  ]);

  const visibleReports = useMemo(() => {
    const selectedId = selectedReport?._id;
    const reportById = new Map<string, TrashReport>();

    reports
      .filter(shouldShowReportOnMap)
      .forEach((report) => reportById.set(report._id, report));

    if (selectedReport && shouldShowReportOnMap(selectedReport)) {
      reportById.set(selectedReport._id, selectedReport);
    }

    return Array.from(reportById.values())
      .map((report) =>
        ({
          ...report,
          distanceMeters: getDistanceMeters(reportFetchCenter, {
            lat: report.location.lat,
            lng: report.location.lng,
          }),
        })
      )
      .filter(
        (report) => {
          const isSelected = report._id === selectedId;
          const matchesFilter =
            activeFilter === "ALL" || report.status === activeFilter;
          const isNearVisibleArea =
            (report.distanceMeters ?? 0) <= REPORT_MAX_DISTANCE_METERS;

          return isSelected || (matchesFilter && isNearVisibleArea);
        }
      )
      .sort((a, b) => {
        if (a._id === selectedId) {
          return -1;
        }

        if (b._id === selectedId) {
          return 1;
        }

        return (a.distanceMeters ?? 0) - (b.distanceMeters ?? 0);
      })
      .slice(0, REPORT_LIMIT);
  }, [activeFilter, reportFetchCenter, reports, selectedReport]);

  const nearbyReports = useMemo(() => {
    const nearbyOrigin = userLocation ?? reportFetchCenter;

    return reports
      .filter(shouldShowReportOnMap)
      .map((report) => ({
        ...report,
        distanceMeters: getDistanceMeters(nearbyOrigin, {
          lat: report.location.lat,
          lng: report.location.lng,
        }),
      }))
      .filter(
        (report) =>
          (report.distanceMeters ?? 0) <= REPORT_MAX_DISTANCE_METERS &&
          (activeFilter === "ALL" || report.status === activeFilter)
      )
      .sort((a, b) => (a.distanceMeters ?? 0) - (b.distanceMeters ?? 0))
      .slice(0, 4);
  }, [activeFilter, reportFetchCenter, reports, userLocation]);

  const handleSelectReport = (report: TrashReport) => {
    setSelectedReport(report);
    setDetailOpen(true);
  };

  const handleLocateMe = () => {
    if (!navigator.geolocation) {
      toast.error("Trình duyệt chưa hỗ trợ định vị");
      return;
    }

    setLocating(true);
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const nextLocation = {
          lat: position.coords.latitude,
          lng: position.coords.longitude,
        };
        setUserLocation(nextLocation);
        setCurrentCenter(nextLocation);
        setReportQueryCenter(nextLocation);
        setFlyTarget({ ...nextLocation, zoom: 16 });
        setLocating(false);
      },
      () => {
        toast.error("Không lấy được vị trí hiện tại");
        setLocating(false);
      },
      {
        enableHighAccuracy: true,
        timeout: 12000,
      }
    );
  };

  const searchPlaces = useCallback(async (query: string) => {
    const normalizedQuery = query.trim();
    searchAbortRef.current?.abort();

    if (!normalizedQuery) {
      setSearchResults([]);
      return;
    }

    const cacheKey = normalizedQuery.toLowerCase();

    if (searchCacheRef.current[cacheKey]) {
      setSearchResults(searchCacheRef.current[cacheKey]);
      return;
    }

    const controller = new AbortController();
    searchAbortRef.current = controller;

    try {
      setSearching(true);
      const response = await fetch(
        `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(
          normalizedQuery
        )}&limit=5`,
        { signal: controller.signal }
      );
      const results = (await response.json()) as SearchResult[];
      searchCacheRef.current[cacheKey] = results;
      setSearchResults(results);
    } catch (error) {
      if (isAbortError(error)) {
        return;
      }

      console.error(error);
      toast.error("Không tìm được địa điểm");
    } finally {
      if (searchAbortRef.current === controller) {
        setSearching(false);
      }
    }
  }, []);

  useEffect(() => {
    const query = searchQuery.trim();

    if (query.length < 3) {
      searchAbortRef.current?.abort();
      setSearching(false);
      setSearchResults([]);
      return;
    }

    const timer = window.setTimeout(() => {
      searchPlaces(query);
    }, 450);

    return () => window.clearTimeout(timer);
  }, [searchPlaces, searchQuery]);

  const handleSearchSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await searchPlaces(searchQuery);
  };

  const handlePickSearchResult = (result: SearchResult) => {
    const lat = Number(result.lat);
    const lng = Number(result.lon);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return;
    }

    setSearchQuery(result.display_name.split(",")[0]);
    setSearchResults([]);
    setCurrentCenter({ lat, lng });
    setReportQueryCenter({ lat, lng });
    setFlyTarget({ lat, lng, zoom: 15 });
  };

  const startReporting = () => {
    setMapMode("reporting");
    setDraftLocation(null);
  };

  const cancelReporting = () => {
    setMapMode("view");
    setDraftLocation(null);
    setCreateOpen(false);
  };

  const confirmDraftLocation = () => {
    setDraftLocation(currentCenter);
    setCreateOpen(true);
  };

  const resetCreateForm = () => {
    setDescription("");
    setTrashType("plastic");
    setSeverity("medium");
    setReportImages([]);
  };

  const handleCreateReport = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!draftLocation) {
      toast.error("Bạn chưa chọn vị trí báo rác");
      return;
    }

    try {
      setSubmittingReport(true);
      const createdReport = await reportService.createReport(
        {
          description,
          type: trashType,
          severity,
          lat: draftLocation.lat,
          lng: draftLocation.lng,
        },
        reportImages
      );
      upsertReport(createdReport);
      setSelectedReport(createdReport);
      setDetailOpen(true);
      setFlyTarget({
        lat: createdReport.location.lat,
        lng: createdReport.location.lng,
        zoom: 17,
      });
      resetCreateForm();
      setCreateOpen(false);
      setDraftLocation(null);
      setMapMode("view");
      toast.success("Đã tạo báo cáo điểm rác");
    } catch (error) {
      console.error(error);
      toast.error("Không tạo được báo cáo");
    } finally {
      setSubmittingReport(false);
    }
  };

  const handleVerifyReport = async () => {
    if (!selectedReport || !user) {
      return;
    }

    const previousReport = selectedReport;
    const alreadyVerified = selectedReport.verifications.some(
      (item) => item.userId === user._id
    );
    const optimisticVerifications = alreadyVerified
      ? selectedReport.verifications
      : [
          ...selectedReport.verifications,
          { userId: user._id, createdAt: new Date().toISOString() },
        ];
    const optimisticReport: TrashReport = {
      ...selectedReport,
      verifications: optimisticVerifications,
      status:
        selectedReport.status === "ACTIVE" && optimisticVerifications.length >= 2
          ? "VERIFIED"
          : selectedReport.status,
      updatedAt: new Date().toISOString(),
    };
    let shouldRollbackReport = true;

    try {
      setReportActionLoading(selectedReport._id, true);
      upsertReport(optimisticReport);
      const updated = await reportService.verifyReport(selectedReport._id);
      upsertReport(updated);
      shouldRollbackReport = false;
      toast.success("Đã xác nhận điểm rác");
    } catch (error) {
      console.error(error);
      toast.error("Không xác nhận được điểm rác");
    } finally {
      if (shouldRollbackReport) {
        upsertReport(previousReport);
      }

      setReportActionLoading(selectedReport._id, false);
    }
  };

  const handleConfirmClean = async () => {
    if (!selectedReport || !user) {
      return;
    }

    const previousReport = selectedReport;
    const alreadyConfirmed = selectedReport.cleanupConfirmations.some(
      (item) => item.userId === user._id
    );
    const optimisticConfirmations = alreadyConfirmed
      ? selectedReport.cleanupConfirmations
      : [
          ...selectedReport.cleanupConfirmations,
          { userId: user._id, createdAt: new Date().toISOString() },
        ];
    const becameCleaned = optimisticConfirmations.length >= 2;
    const optimisticReport: TrashReport = {
      ...selectedReport,
      cleanupConfirmations: optimisticConfirmations,
      status: becameCleaned ? "CLEANED" : selectedReport.status,
      cleanedAt: becameCleaned
        ? selectedReport.cleanedAt ?? new Date().toISOString()
        : selectedReport.cleanedAt,
      updatedAt: new Date().toISOString(),
    };
    let shouldRollbackReport = true;

    try {
      setReportActionLoading(selectedReport._id, true);
      upsertReport(optimisticReport);
      const updated = await reportService.confirmClean(selectedReport._id);
      upsertReport(updated);
      shouldRollbackReport = false;
      toast.success("Đã xác nhận sạch");
    } catch (error) {
      console.error(error);
      toast.error("Không xác nhận sạch được");
    } finally {
      if (shouldRollbackReport) {
        upsertReport(previousReport);
      }

      setReportActionLoading(selectedReport._id, false);
    }
  };

  const handleCleanupReport = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!selectedReport || !user) {
      return;
    }

    const previousReport = selectedReport;
    const optimisticReport: TrashReport = {
      ...selectedReport,
      status: "CLEANUP_PENDING",
      cleanupConfirmations: [],
      cleanedAt: null,
      cleanup: {
        ...selectedReport.cleanup,
        cleanedBy: user,
        beforeImages: selectedReport.images,
        description: cleanupDescription,
        createdAt: new Date().toISOString(),
      },
      updatedAt: new Date().toISOString(),
    };
    let shouldRollbackReport = true;

    try {
      setCleaning(true);
      setReportActionLoading(selectedReport._id, true);
      upsertReport(optimisticReport);
      const updated = await reportService.cleanupReport(selectedReport._id, {
        description: cleanupDescription,
        images: cleanupImages,
      });
      upsertReport(updated);
      shouldRollbackReport = false;
      setCleanupOpen(false);
      setCleanupDescription("");
      setCleanupImages([]);
      toast.success("Đã báo điểm rác được dọn");
    } catch (error) {
      console.error(error);
      toast.error("Không gửi được báo cáo dọn rác");
    } finally {
      if (shouldRollbackReport) {
        upsertReport(previousReport);
      }

      setReportActionLoading(selectedReport._id, false);
      setCleaning(false);
    }
  };

  const handleAddComment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!selectedReport || !commentText.trim()) {
      return;
    }

    try {
      setCommenting(true);
      const comment = await reportService.addComment(
        selectedReport._id,
        commentText
      );
      setComments((prev) => [...prev, comment]);
      setCommentText("");
      await syncReport(selectedReport._id);
    } catch (error) {
      console.error(error);
      toast.error("Không gửi được bình luận");
    } finally {
      setCommenting(false);
    }
  };

  const handleShareReport = async () => {
    if (!selectedReport) {
      return;
    }

    const target =
      shareMode === "friend"
        ? { targetUserId: shareFriendId }
        : { conversationId: shareConversationId };

    if (
      (shareMode === "friend" && !shareFriendId) ||
      (shareMode === "conversation" && !shareConversationId)
    ) {
      toast.error("Bạn chưa chọn nơi nhận");
      return;
    }

    try {
      setSharing(true);
      const result = await reportService.shareReport(selectedReport._id, target);

      if (result.conversation) {
        addConvo(result.conversation);
        socket?.emit("join-conversation", result.conversation._id);
      }

      toast.success("Đã chia sẻ điểm rác vào chat");
      setShareOpen(false);
    } catch (error) {
      console.error(error);
      toast.error("Không chia sẻ được điểm rác");
    } finally {
      setSharing(false);
    }
  };

  const handleJoinChat = async () => {
    if (!selectedReport) {
      return;
    }

    try {
      const { conversation } = await reportService.joinReportChat(
        selectedReport._id
      );
      addConvo(conversation);
      setActiveConversation(conversation._id);
      socket?.emit("join-conversation", conversation._id);
      await fetchMessages(conversation._id);
      navigate("/");
    } catch (error) {
      console.error(error);
      toast.error("Không mở được nhóm xử lý");
    }
  };

  const handleInviteFriends = async () => {
    if (!selectedReport || inviteFriendIds.length === 0) {
      toast.error("Bạn chưa chọn bạn bè để mời");
      return;
    }

    try {
      setInviting(true);
      const { conversation, invitedIds } =
        await reportService.inviteReportChatMembers(
          selectedReport._id,
          inviteFriendIds
        );
      addConvo(conversation);
      socket?.emit("join-conversation", conversation._id);
      setInviteOpen(false);
      setInviteFriendIds([]);
      toast.success(
        invitedIds.length > 0
          ? `Đã gửi ${invitedIds.length} lời mời vào nhóm xử lý`
          : "Những bạn này đã ở trong nhóm hoặc đã có lời mời chờ xử lý"
      );
    } catch (error) {
      console.error(error);
      toast.error("Không mời được bạn bè vào nhóm");
    } finally {
      setInviting(false);
    }
  };

  const toggleInviteFriend = (friendId: string) => {
    setInviteFriendIds((prev) =>
      prev.includes(friendId)
        ? prev.filter((id) => id !== friendId)
        : [...prev, friendId]
    );
  };

  const handleSendFriendRequestFromProfile = async () => {
    if (!miniProfileUser) {
      return;
    }

    try {
      setAddingFriend(true);
      const message = await addFriend(
        miniProfileUser._id,
        "Mình thấy bạn trong một điểm báo rác trên Moji Eco."
      );
      toast.success(message || "Đã gửi lời mời kết bạn");
    } catch (error) {
      console.error(error);
      toast.error("Không gửi được lời mời kết bạn");
    } finally {
      setAddingFriend(false);
    }
  };

  const handleMessageProfileUser = async () => {
    if (!miniProfileUser) {
      return;
    }

    const conversation = conversations.find(
      (item) =>
        item.type === "direct" &&
        item.participants.some((participant) => participant._id === miniProfileUser._id)
    );

    if (conversation) {
      setActiveConversation(conversation._id);
      await fetchMessages(conversation._id);
      navigate("/");
      return;
    }

    toast.info("Hãy kết bạn hoặc share report cho người này để tạo cuộc trò chuyện.");
  };

  const selectedStatusMeta = selectedReport
    ? STATUS_META[selectedReport.status]
    : null;
  const selectedImage = selectedReport?.images?.[0];
  const selectedReportActionLoading = selectedReport
    ? Boolean(reportActionLoadingById[selectedReport._id])
    : false;

  return (
    <main className="relative isolate h-full min-h-0 flex-1 overflow-hidden rounded-2xl border border-border/60 bg-background shadow-soft">
      <MapContainer
        center={[DEFAULT_CENTER.lat, DEFAULT_CENTER.lng]}
        zoom={13}
        zoomControl={false}
        className="z-0 h-full w-full"
      >
        <TileLayer
          key={mapStyle}
          attribution={TILE_LAYERS[mapStyle].attribution}
          url={TILE_LAYERS[mapStyle].url}
        />
        <MapFlyTo target={flyTarget} />
        <MapCenterWatcher
          enabled
          live={mapMode === "reporting"}
          onCenterChange={setCurrentCenter}
          onIdleCenterChange={setReportQueryCenter}
        />

        {visibleReports.map((report) => (
          <Marker
            key={report._id}
            position={[report.location.lat, report.location.lng]}
            icon={markerIcons[report.status]}
            eventHandlers={{
              click: () => handleSelectReport(report),
            }}
          />
        ))}

        {userLocation && (
          <Marker
            position={[userLocation.lat, userLocation.lng]}
            icon={userLocationIcon}
          />
        )}
      </MapContainer>

      <div className="pointer-events-none absolute inset-x-3 top-3 z-[450] mx-auto flex max-w-3xl flex-col items-center gap-2">
        <form
          onSubmit={handleSearchSubmit}
          className="pointer-events-auto relative flex w-full max-w-xl min-w-0 items-center gap-1 rounded-2xl border border-emerald-200/80 bg-background/95 px-3 py-2 shadow-soft backdrop-blur sm:gap-2 sm:rounded-full"
        >
          <Search className="size-4 text-muted-foreground" />
          <Input
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Tìm địa điểm"
            className="h-8 min-w-0 border-0 bg-transparent px-1 shadow-none focus-visible:ring-0"
          />
          <Button
            type="button"
            variant={filtersOpen ? "secondary" : "ghost"}
            size="icon"
            className="size-8 shrink-0 rounded-full"
            onClick={() => setFiltersOpen((open) => !open)}
            title={filtersOpen ? "Ẩn bộ lọc" : "Hiện bộ lọc"}
          >
            <SlidersHorizontal className="size-4" />
          </Button>
          <Button
            type="submit"
            size="sm"
            className="h-8 shrink-0 rounded-full px-3"
            disabled={searching}
          >
            {searching ? <Loader2 className="size-4 animate-spin" /> : "Tìm"}
          </Button>

          {searchResults.length > 0 && (
            <div className="absolute left-0 right-0 top-[calc(100%+8px)] max-h-[45vh] overflow-y-auto overflow-x-hidden rounded-xl border border-border bg-background shadow-soft">
              {searchResults.map((result) => (
                <button
                  key={result.place_id}
                  type="button"
                  className="flex w-full items-start gap-2 px-4 py-3 text-left text-sm transition hover:bg-muted"
                  onClick={() => handlePickSearchResult(result)}
                >
                  <MapPin className="mt-0.5 size-4 shrink-0 text-primary" />
                  <span className="line-clamp-2">{result.display_name}</span>
                </button>
              ))}
            </div>
          )}
        </form>

        {filtersOpen && searchResults.length === 0 && (
          <div className="pointer-events-auto flex max-w-full gap-2 overflow-x-auto rounded-full border border-border/70 bg-background/90 p-1 shadow-soft backdrop-blur">
            {FILTERS.map((filter) => (
              <Button
                key={filter.value}
                type="button"
                variant={activeFilter === filter.value ? "default" : "ghost"}
                size="sm"
                className="h-8 shrink-0 rounded-full px-3"
                onClick={() => setActiveFilter(filter.value)}
              >
                {filter.label}
              </Button>
            ))}
          </div>
        )}
      </div>

      <Button
        type="button"
        variant="secondary"
        className="absolute left-3 top-[7rem] z-[450] h-10 rounded-full border border-border/80 bg-background/95 px-3 shadow-soft backdrop-blur md:hidden"
        onClick={() => navigate("/")}
      >
        <ArrowLeft className="size-4" />
        Quay lại chat
      </Button>

      <Button
        type="button"
        variant="secondary"
        size="icon"
        className="absolute right-3 top-[7rem] z-[450] size-11 rounded-full border border-border/80 bg-background/95 shadow-soft backdrop-blur md:right-4 md:top-4"
        onClick={() => setMapStyle(mapStyle === "street" ? "light" : "street")}
        title="Đổi chế độ street/light"
      >
        <Layers className="size-5" />
      </Button>

      {loadingReports && (
        <div className="absolute left-1/2 top-[10.25rem] z-[450] flex -translate-x-1/2 items-center gap-2 rounded-full border border-border bg-background/95 px-3 py-2 text-sm shadow-soft md:left-4 md:top-4 md:translate-x-0">
          <Loader2 className="size-4 animate-spin text-primary" />
          Đang tải
        </div>
      )}

      {mapMode === "reporting" && (
        <>
          <div className="pointer-events-none absolute inset-0 z-[430] bg-emerald-950/10" />
          <div className="pointer-events-none absolute left-1/2 top-1/2 z-[460] -translate-x-1/2 -translate-y-full">
            <div className="flex size-14 items-center justify-center rounded-full bg-red-500 text-white shadow-[0_16px_40px_rgba(239,68,68,0.38)]">
              <Trash2 className="size-7" />
            </div>
            <div className="mx-auto h-8 w-1 rounded-b-full bg-red-500" />
          </div>
          <div className="absolute bottom-[calc(env(safe-area-inset-bottom)+5rem)] left-1/2 z-[470] flex w-[calc(100%-1.5rem)] max-w-sm -translate-x-1/2 gap-2 rounded-2xl border border-border bg-background/95 p-2 shadow-soft backdrop-blur sm:bottom-24 sm:w-auto sm:rounded-full">
            <Button
              type="button"
              variant="outline"
              className="rounded-full"
              onClick={cancelReporting}
            >
              <X className="size-4" />
              Hủy
            </Button>
            <Button
              type="button"
              className="rounded-full"
              onClick={confirmDraftLocation}
            >
              <CheckCircle2 className="size-4" />
              Xác nhận vị trí
            </Button>
          </div>
        </>
      )}

      <div className="absolute bottom-[calc(env(safe-area-inset-bottom)+5.25rem)] right-3 z-[450] flex flex-col gap-2 sm:bottom-5 sm:right-4">
        <Button
          type="button"
          variant="secondary"
          size="icon"
          className="size-10 rounded-full border border-border/80 bg-background/95 shadow-soft backdrop-blur"
          onClick={handleLocateMe}
          disabled={locating}
          title="Lấy vị trí hiện tại"
        >
          {locating ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <Crosshair className="size-4" />
          )}
        </Button>
      </div>

      <Button
        type="button"
        className="absolute bottom-[calc(env(safe-area-inset-bottom)+1rem)] left-1/2 z-[450] h-12 -translate-x-1/2 rounded-full bg-red-500 px-6 text-white shadow-[0_18px_45px_rgba(239,68,68,0.32)] hover:bg-red-600 sm:bottom-5"
        onClick={startReporting}
      >
        <Trash2 className="size-5" />
        Báo rác
      </Button>

      <div className="absolute bottom-5 left-4 z-[440] hidden max-h-[34vh] w-60 overflow-hidden rounded-xl border border-border/70 bg-background/95 p-2 shadow-soft backdrop-blur lg:block">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-foreground">Gần tôi</h2>
          <Navigation className="size-3.5 text-primary" />
        </div>
        {nearbyReports.length > 0 ? (
          <div className="max-h-[28vh] space-y-1 overflow-y-auto pr-1">
            {nearbyReports.map((report) => (
              <button
                key={report._id}
                type="button"
                className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition hover:bg-muted"
                onClick={() => {
                  handleSelectReport(report);
                  setFlyTarget({
                    lat: report.location.lat,
                    lng: report.location.lng,
                    zoom: 16,
                  });
                }}
              >
                <span
                  className={cn(
                    "size-2.5 rounded-full",
                    report.status === "ACTIVE" && "bg-red-500",
                    report.status === "VERIFIED" && "bg-orange-500",
                    report.status === "CLEANUP_PENDING" && "bg-sky-500",
                    report.status === "CLEANED" && "bg-emerald-500"
                  )}
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs font-medium">
                    {report.title}
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {formatDistance(report.distanceMeters)}
                  </span>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Bấm định vị để xem các điểm gần bạn.
          </p>
        )}
      </div>

      <Dialog
        open={createOpen}
        onOpenChange={(open) => {
          setCreateOpen(open);
          if (!open && mapMode === "reporting") {
            setMapMode("view");
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <form onSubmit={handleCreateReport}>
            <DialogHeader>
              <DialogTitle>Tạo báo cáo rác</DialogTitle>
              <DialogDescription>
                {draftLocation
                  ? `${draftLocation.lat.toFixed(5)}, ${draftLocation.lng.toFixed(5)}`
                  : "Chưa chọn vị trí"}
              </DialogDescription>
            </DialogHeader>

            <div className="mt-4 space-y-4">
              <Textarea
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="Mô tả loại rác, mùi, vị trí dễ nhận biết..."
                required
                className="min-h-28"
              />

              <div className="grid gap-3 sm:grid-cols-2">
                <label className="space-y-1 text-sm font-medium">
                  Loại rác
                  <select
                    value={trashType}
                    onChange={(event) => setTrashType(event.target.value as TrashType)}
                    className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                  >
                    {Object.entries(TYPE_LABELS).map(([value, label]) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {label}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="space-y-1 text-sm font-medium">
                  Mức độ
                  <select
                    value={severity}
                    onChange={(event) =>
                      setSeverity(event.target.value as TrashSeverity)
                    }
                    className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                  >
                    {Object.entries(SEVERITY_LABELS).map(([value, label]) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <label className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-dashed border-border p-3 text-sm">
                <span className="flex items-center gap-2">
                  <ImagePlus className="size-4 text-primary" />
                  {reportImages.length > 0
                    ? `${reportImages.length} ảnh đã chọn`
                    : "Thêm ảnh"}
                </span>
                <Input
                  type="file"
                  accept="image/*"
                  multiple
                  className="hidden"
                  onChange={(event) =>
                    setReportImages(Array.from(event.target.files || []))
                  }
                />
              </label>
            </div>

            <DialogFooter className="mt-5">
              <Button
                type="button"
                variant="outline"
                onClick={cancelReporting}
                disabled={submittingReport}
              >
                Hủy
              </Button>
              <Button
                type="submit"
                disabled={submittingReport || !description.trim()}
              >
                {submittingReport ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Send className="size-4" />
                )}
                Gửi báo cáo
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Sheet
        open={detailOpen}
        onOpenChange={setDetailOpen}
      >
        <SheetContent
          side="right"
          className="w-full overflow-y-auto p-0 sm:max-w-md"
        >
          {selectedReport && selectedStatusMeta && (
            <div className="flex min-h-full flex-col">
              {selectedImage ? (
                <img
                  src={selectedImage}
                  alt={selectedReport.title}
                  className="h-48 w-full object-cover"
                />
              ) : (
                <div className="flex h-40 items-center justify-center bg-muted">
                  <Trash2 className="size-12 text-muted-foreground" />
                </div>
              )}

              <SheetHeader className="border-b border-border/70">
                <div className="flex items-start justify-between gap-3 pr-8">
                  <div>
                    <SheetTitle className="text-xl">
                      {selectedReport.title}
                    </SheetTitle>
                    <SheetDescription className="mt-1">
                      {selectedReport.createdBy?.displayName || "Moji user"}
                    </SheetDescription>
                  </div>
                  <Badge
                    variant="outline"
                    className={cn("shrink-0", selectedStatusMeta.badgeClass)}
                  >
                    {selectedStatusMeta.label}
                  </Badge>
                </div>
              </SheetHeader>

              <div className="space-y-5 p-4">
                <p className="text-sm leading-6 text-foreground">
                  {selectedReport.description}
                </p>

                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-xl border border-border/70 p-3">
                    <p className="text-xs text-muted-foreground">Loại rác</p>
                    <p className="font-medium">{TYPE_LABELS[selectedReport.type]}</p>
                  </div>
                  <div className="rounded-xl border border-border/70 p-3">
                    <p className="text-xs text-muted-foreground">Mức độ</p>
                    <p className="font-medium">
                      {SEVERITY_LABELS[selectedReport.severity]}
                    </p>
                  </div>
                  <div className="rounded-xl border border-border/70 p-3">
                    <p className="text-xs text-muted-foreground">Xác nhận</p>
                    <p className="font-medium">
                      {selectedReport.verifications.length}/2
                    </p>
                  </div>
                  <div className="rounded-xl border border-border/70 p-3">
                    <p className="text-xs text-muted-foreground">Sạch</p>
                    <p className="font-medium">
                      {selectedReport.cleanupConfirmations.length}/2
                    </p>
                  </div>
                </div>

                <div className="grid gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleVerifyReport}
                    disabled={
                      selectedReportActionLoading ||
                      selectedReport.status === "CLEANED"
                    }
                  >
                    {selectedReportActionLoading ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <CheckCircle2 className="size-4" />
                    )}
                    Xác nhận đúng rác
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setCleanupOpen(true)}
                    disabled={
                      selectedReportActionLoading ||
                      selectedReport.status === "CLEANED"
                    }
                  >
                    <Trash2 className="size-4" />
                    Tôi đã dọn
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleConfirmClean}
                    disabled={
                      selectedReportActionLoading ||
                      selectedReport.status !== "CLEANUP_PENDING"
                    }
                  >
                    {selectedReportActionLoading ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <CheckCircle2 className="size-4" />
                    )}
                    Xác nhận đã sạch
                  </Button>
                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      type="button"
                      onClick={handleJoinChat}
                    >
                      <MessageCircle className="size-4" />
                      Vào chat
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => setShareOpen(true)}
                    >
                      <Share2 className="size-4" />
                      Share
                    </Button>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setInviteOpen(true)}
                  >
                    <UserPlus className="size-4" />
                    Mời bạn bè vào nhóm xử lý
                  </Button>
                </div>

                <section className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">Bình luận</h3>
                    {loadingComments && (
                      <Loader2 className="size-4 animate-spin text-primary" />
                    )}
                  </div>

                  <div className="max-h-64 space-y-3 overflow-y-auto pr-1">
                    {comments.length > 0 ? (
                      comments.map((comment) => (
                        <div
                          key={comment._id}
                          className="rounded-xl bg-muted/70 p-3"
                        >
                          <button
                            type="button"
                            className="mb-1 flex items-center gap-2 text-left"
                            onClick={() => setMiniProfileUser(comment.userId)}
                          >
                            <Avatar className="size-7">
                              <AvatarImage src={comment.userId.avatarUrl} />
                              <AvatarFallback>
                                {getInitials(comment.userId.displayName)}
                              </AvatarFallback>
                            </Avatar>
                            <span className="font-medium">
                              {comment.userId.displayName}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {new Date(comment.createdAt).toLocaleTimeString(
                                "vi-VN",
                                {
                                  hour: "2-digit",
                                  minute: "2-digit",
                                }
                              )}
                            </span>
                          </button>
                          <p className="text-sm leading-5">{comment.content}</p>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        Chưa có bình luận.
                      </p>
                    )}
                  </div>

                  <form
                    onSubmit={handleAddComment}
                    className="flex items-center gap-2"
                  >
                    <Input
                      value={commentText}
                      onChange={(event) => setCommentText(event.target.value)}
                      placeholder="Viết bình luận"
                    />
                    <Button
                      type="submit"
                      size="icon"
                      disabled={commenting || !commentText.trim()}
                    >
                      {commenting ? (
                        <Loader2 className="size-4 animate-spin" />
                      ) : (
                        <Send className="size-4" />
                      )}
                    </Button>
                  </form>
                </section>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      <Dialog
        open={cleanupOpen}
        onOpenChange={setCleanupOpen}
      >
        <DialogContent className="sm:max-w-md">
          <form onSubmit={handleCleanupReport}>
            <DialogHeader>
              <DialogTitle>Báo đã dọn</DialogTitle>
              <DialogDescription>
                Gửi ảnh sau khi dọn để cộng đồng xác nhận.
              </DialogDescription>
            </DialogHeader>
            <div className="mt-4 space-y-3">
              <Textarea
                value={cleanupDescription}
                onChange={(event) => setCleanupDescription(event.target.value)}
                placeholder="Ghi chú sau khi dọn"
              />
              <label className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-dashed border-border p-3 text-sm">
                <span className="flex items-center gap-2">
                  <ImagePlus className="size-4 text-primary" />
                  {cleanupImages.length > 0
                    ? `${cleanupImages.length} ảnh đã chọn`
                    : "Thêm ảnh sau dọn"}
                </span>
                <Input
                  type="file"
                  accept="image/*"
                  multiple
                  className="hidden"
                  onChange={(event) =>
                    setCleanupImages(Array.from(event.target.files || []))
                  }
                />
              </label>
            </div>
            <DialogFooter className="mt-5">
              <Button
                type="button"
                variant="outline"
                onClick={() => setCleanupOpen(false)}
                disabled={cleaning}
              >
                Hủy
              </Button>
              <Button
                type="submit"
                disabled={cleaning}
              >
                {cleaning ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <CheckCircle2 className="size-4" />
                )}
                Gửi
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={shareOpen}
        onOpenChange={setShareOpen}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Share qua chat</DialogTitle>
            <DialogDescription>
              Gửi card điểm rác vào cuộc trò chuyện hoặc gửi thẳng cho bạn bè.
            </DialogDescription>
          </DialogHeader>
          <div className="mt-3 space-y-3">
            <div className="grid grid-cols-2 gap-2 rounded-xl bg-muted p-1">
              <Button
                type="button"
                variant={shareMode === "conversation" ? "default" : "ghost"}
                size="sm"
                onClick={() => setShareMode("conversation")}
              >
                <MessageCircle className="size-4" />
                Conversation
              </Button>
              <Button
                type="button"
                variant={shareMode === "friend" ? "default" : "ghost"}
                size="sm"
                onClick={() => setShareMode("friend")}
              >
                <Users className="size-4" />
                Bạn bè
              </Button>
            </div>

            {shareMode === "conversation" ? (
              <>
                <select
                  value={shareConversationId}
                  onChange={(event) => setShareConversationId(event.target.value)}
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  {conversations.map((conversation) => (
                    <option
                      key={conversation._id}
                      value={conversation._id}
                    >
                      {getConversationName(conversation, user?._id)}
                    </option>
                  ))}
                </select>
                {conversations.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    Bạn chưa có cuộc trò chuyện để chia sẻ.
                  </p>
                )}
              </>
            ) : (
              <>
                <select
                  value={shareFriendId}
                  onChange={(event) => setShareFriendId(event.target.value)}
                  className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  {friends.map((friend) => (
                    <option
                      key={friend._id}
                      value={friend._id}
                    >
                      {friend.displayName}
                    </option>
                  ))}
                </select>
                {friends.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    Bạn chưa có bạn bè để gửi trực tiếp.
                  </p>
                )}
              </>
            )}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setShareOpen(false)}
              disabled={sharing}
            >
              Hủy
            </Button>
            <Button
              type="button"
              onClick={handleShareReport}
              disabled={
                sharing ||
                (shareMode === "conversation" && !shareConversationId) ||
                (shareMode === "friend" && !shareFriendId)
              }
            >
              {sharing ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Share2 className="size-4" />
              )}
              Chia sẻ
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={inviteOpen}
        onOpenChange={setInviteOpen}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Mời bạn bè xử lý</DialogTitle>
            <DialogDescription>
              Bạn bè cần đồng ý lời mời trước khi được thêm vào nhóm cleanup.
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
            {friends.length > 0 ? (
              friends.map((friend) => {
                const checked = inviteFriendIds.includes(friend._id);

                return (
                  <button
                    key={friend._id}
                    type="button"
                    className={cn(
                      "flex w-full items-center gap-3 rounded-xl border p-3 text-left transition",
                      checked
                        ? "border-primary bg-primary/10"
                        : "border-border hover:bg-muted"
                    )}
                    onClick={() => toggleInviteFriend(friend._id)}
                  >
                    <Avatar className="size-9">
                      <AvatarImage src={friend.avatarUrl} />
                      <AvatarFallback>{getInitials(friend.displayName)}</AvatarFallback>
                    </Avatar>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium">
                        {friend.displayName}
                      </span>
                      <span className="block truncate text-xs text-muted-foreground">
                        @{friend.username}
                      </span>
                    </span>
                    <span
                      className={cn(
                        "size-4 rounded-full border",
                        checked && "border-primary bg-primary"
                      )}
                    />
                  </button>
                );
              })
            ) : (
              <p className="rounded-xl bg-muted p-3 text-sm text-muted-foreground">
                Bạn chưa có bạn bè để mời.
              </p>
            )}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setInviteOpen(false)}
              disabled={inviting}
            >
              Hủy
            </Button>
            <Button
              type="button"
              onClick={handleInviteFriends}
              disabled={inviting || inviteFriendIds.length === 0}
            >
              {inviting ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <UserPlus className="size-4" />
              )}
              Gửi lời mời
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={Boolean(miniProfileUser)}
        onOpenChange={(open) => !open && setMiniProfileUser(null)}
      >
        <DialogContent className="sm:max-w-sm">
          {miniProfileUser && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-3">
                  <Avatar className="size-12">
                    <AvatarImage src={miniProfileUser.avatarUrl} />
                    <AvatarFallback>
                      {getInitials(miniProfileUser.displayName)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="min-w-0">
                    <DialogTitle className="truncate">
                      {miniProfileUser.displayName}
                    </DialogTitle>
                    <DialogDescription className="truncate">
                      @{miniProfileUser.username}
                    </DialogDescription>
                  </div>
                </div>
              </DialogHeader>

              {miniProfileUser.bio && (
                <p className="text-sm leading-6 text-muted-foreground">
                  {miniProfileUser.bio}
                </p>
              )}

              <div className="grid gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleSendFriendRequestFromProfile}
                  disabled={addingFriend || miniProfileUser._id === user?._id}
                >
                  {addingFriend ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <UserPlus className="size-4" />
                  )}
                  Gửi lời mời kết bạn
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleMessageProfileUser}
                  disabled={miniProfileUser._id === user?._id}
                >
                  <MessageCircle className="size-4" />
                  Nhắn tin riêng
                </Button>
                <Button
                  type="button"
                  onClick={() => {
                    setInviteFriendIds([miniProfileUser._id]);
                    setMiniProfileUser(null);
                    setInviteOpen(true);
                  }}
                  disabled={miniProfileUser._id === user?._id}
                >
                  <Users className="size-4" />
                  Mời vào nhóm xử lý
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </main>
  );
};

export default EcoMapPage;
