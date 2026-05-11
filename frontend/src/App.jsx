import { useEffect, useMemo, useRef, useState, useTransition } from "react";
import MagicBento from "./MagicBento";
import brandLogo from "./assets/brand-logo.png";

const DEFAULT_IMAGE = "nginx:latest";
const NAV_ITEMS = [
  { key: "dashboard", label: "Dashboard", path: "/", blurb: "Live posture and scan summary" },
  { key: "history", label: "History", path: "/history", blurb: "Saved records and drill-downs" },
  { key: "reports", label: "Reports", path: "/reports", blurb: "Aggregate trends and exposure" },
  { key: "vulnerabilities", label: "Vulnerabilities", path: "/vulnerabilities", blurb: "CVEs and image findings" },
  { key: "cis", label: "CIS Benchmark", path: "/cis", blurb: "Compliance control status" },
  { key: "secrets", label: "Secrets Detection", path: "/secrets", blurb: "Credential and token findings" },
  { key: "supply_chain", label: "Supply Chain", path: "/supply-chain", blurb: "Provenance and dependency risk" },
  { key: "runtime", label: "Runtime Security", path: "/runtime", blurb: "Runtime configuration checks" },
  { key: "export", label: "Export Center", path: "/export", blurb: "Generate and archive report exports" },
  { key: "scheduled", label: "Scheduled Scans", path: "/scheduled", blurb: "Queued and scheduled scan activity" },
  { key: "admin", label: "Admin", path: "/admin", blurb: "Users and organization activity" },
  { key: "settings", label: "Settings", path: "/settings", blurb: "Runtime and platform defaults" }
];
const SIDEBAR_GROUPS = [
  {
    label: "Scan",
    items: [
      { type: "route", key: "dashboard", label: "Dashboard", path: "/", icon: "home" },
      { type: "action", label: "Quick Scan", path: "#quick-scan", badge: "New", icon: "zap" },
      { type: "action", label: "Image Scan", path: "#quick-scan", icon: "image" },
      { type: "action", label: "Host Scan", path: "#quick-scan", icon: "monitor" },
      { type: "action", label: "Registry Scan", path: "#quick-scan", icon: "server" },
      { type: "action", label: "K8s Cluster Scan", path: "#quick-scan", icon: "cluster" }
    ]
  },
  {
    label: "Analyze",
    items: [
      { type: "route", key: "vulnerabilities", label: "Vulnerabilities", path: "/vulnerabilities", icon: "shield" },
      { type: "route", key: "cis", label: "CIS Benchmark", path: "/cis", icon: "check" },
      { type: "route", key: "secrets", label: "Secrets Detection", path: "/secrets", icon: "key" },
      { type: "route", key: "supply_chain", label: "Supply Chain", path: "/supply-chain", icon: "diamond" },
      { type: "route", key: "runtime", label: "Runtime Security", path: "/runtime", icon: "spark" }
    ]
  },
  {
    label: "Manage",
    items: [
      { type: "route", key: "history", label: "Scan History", path: "/history", icon: "history" },
      { type: "route", key: "reports", label: "Reports", path: "/reports", icon: "report" },
      { type: "route", key: "admin", label: "Admin", path: "/admin", icon: "users", adminOnly: true },
      { type: "route", key: "export", label: "Export Center", path: "/export", icon: "export" },
      { type: "route", key: "scheduled", label: "Scheduled Scans", path: "/scheduled", icon: "clock" }
    ]
  },
  {
    label: "System",
    items: [
      { type: "route", key: "settings", label: "Integrations", path: "/settings", icon: "plug" },
      { type: "route", key: "settings", label: "Settings", path: "/settings", icon: "settings" }
    ]
  }
];
const QUICK_IMAGES = ["nginx:latest", "python:3.12-slim", "node:20-bookworm-slim"];
const FILTER_SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const FILTER_MODULES = ["ALL", "cve", "cis", "runtime", "supply_chain", "secrets"];
const ISSUE_PAGE_SIZE = 50;
const ANALYZE_CONFIGS = {
  vulnerabilities: {
    title: "Vulnerabilities",
    description: "Review CVEs from the latest scan in a dedicated page.",
    tableTitle: "CVEs and image findings",
    moduleKey: "cve",
    cardKey: "vuln",
    issueModules: ["cve", "vulnerability", "vulnerabilities"],
    showIssues: true,
    scoreLabel: "Findings",
    icon: "⛨",
    actions: ["Prioritize critical and high CVEs", "Open affected image details", "Generate a report for remediation tracking"]
  },
  cis: {
    title: "CIS Benchmark",
    description: "Inspect compliance controls and failed benchmark checks.",
    tableTitle: "Benchmark checks",
    moduleKey: "cis",
    cardKey: "cis",
    issueModules: ["cis"],
    showIssues: false,
    scoreLabel: "CIS Score",
    icon: "✓",
    actions: ["Review failed controls", "Confirm container hardening", "Track compliance drift"]
  },
  secrets: {
    title: "Secrets Detection",
    description: "Review tokens, keys, credentials, and high-entropy findings.",
    tableTitle: "Secret findings",
    moduleKey: "secrets",
    cardKey: "secrets",
    issueModules: ["secrets", "secret"],
    showIssues: true,
    scoreLabel: "Secrets",
    icon: "⌘",
    actions: ["Rotate exposed credentials", "Remove sensitive files from images", "Re-scan after cleanup"]
  },
  supply_chain: {
    title: "Supply Chain",
    description: "Inspect provenance, mutable tags, and dependency risk checks.",
    tableTitle: "Supply chain checks",
    moduleKey: "supply_chain",
    cardKey: "supply_chain",
    issueModules: ["supply_chain", "supply-chain"],
    showIssues: false,
    scoreLabel: "Health",
    icon: "◇",
    actions: ["Pin mutable tags", "Review provenance gaps", "Check startup command risk"]
  },
  runtime: {
    title: "Runtime Security",
    description: "Review runtime hardening checks and unsafe container settings.",
    tableTitle: "Runtime checks",
    moduleKey: "runtime",
    cardKey: "runtime",
    issueModules: ["runtime"],
    showIssues: false,
    scoreLabel: "Health",
    icon: "✦",
    actions: ["Remove privileged flags", "Review host namespace usage", "Harden mounts and networking"]
  }
};

export default function App() {
  const [route, setRoute] = useState(readRoute());
  const [, startRouteTransition] = useTransition();
  const [sidebarOpen, setSidebarOpen] = useState(() => (typeof window === "undefined" ? true : window.innerWidth > 1180));
  const [image, setImage] = useState(DEFAULT_IMAGE);
  const [sourcePath, setSourcePath] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanProgress, setScanProgress] = useState({
    active: false,
    phase: "",
    module: "",
    percent: 0,
    events: [],
    error: "",
    completed: false
  });
  const [scanResult, setScanResult] = useState(null);
  const [historyState, setHistoryState] = useState({
    loading: true,
    error: "",
    records: []
  });
  const [reportsState, setReportsState] = useState({
    loading: true,
    error: "",
    payload: null,
    archive: []
  });
  const [jobsState, setJobsState] = useState({
    loading: true,
    error: "",
    jobs: []
  });
  const [adminState, setAdminState] = useState({
    loading: false,
    error: "",
    users: [],
    action: ""
  });
  const [adminUserForm, setAdminUserForm] = useState({
    username: "",
    password: "",
    role: "analyst",
    full_name: "",
    email: "",
    job_title: "",
    loading: false,
    error: "",
    success: ""
  });
  const [reportAction, setReportAction] = useState({
    loading: false,
    format: "",
    error: "",
    success: ""
  });
  const [authState, setAuthState] = useState(() => readStoredAuth());
  const [authForm, setAuthForm] = useState({
    username: "",
    password: "",
    mode: "login",
    loading: false,
    error: ""
  });
  const [profileForm, setProfileForm] = useState({
    full_name: authState.user?.full_name || "",
    email: authState.user?.email || "",
    job_title: authState.user?.job_title || "",
    loading: false,
    error: "",
    success: ""
  });
  const [passwordForm, setPasswordForm] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
    loading: false,
    error: "",
    success: ""
  });
  const [latestRecordDetail, setLatestRecordDetail] = useState(null);
  const [scanDetailState, setScanDetailState] = useState({
    loading: false,
    error: "",
    record: null
  });
  const [filters, setFilters] = useState({
    severity: "ALL",
    module: "ALL",
    search: ""
  });
  const [aiState, setAiState] = useState({
    open: false,
    loading: false,
    error: "",
    response: null,
    selectedIssue: null
  });
  const [chatModal, setChatModal] = useState({
    open: false,
    loading: false,
    error: "",
    selectedIssue: null,
    messages: [],
    input: ""
  });
  const [floatingChat, setFloatingChat] = useState({
    open: false,
    loading: false,
    error: "",
    messages: [
      {
        role: "assistant",
        text: "Ask about CVEs, CIS failures, risk scores, or remediation steps."
      }
    ],
    input: ""
  });
  const [dashboardModal, setDashboardModal] = useState({
    open: false,
    type: "",
    title: ""
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const imageInputRef = useRef(null);
  const sourcePathInputRef = useRef(null);

  useEffect(() => {
    function handlePopState() {
      setRoute(readRoute());
    }

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    loadHistory();
    loadJobs();
    if (authState.user?.role === "admin") {
      loadAdminUsers();
    } else {
      setAdminState({ loading: false, error: "", users: [], action: "" });
    }
  }, [authState.token]);

  useEffect(() => {
    if (route.name === "detail" && route.id) {
      loadRecord(route.id);
    }
  }, [route]);

  useEffect(() => {
    setProfileForm((current) => ({
      ...current,
      full_name: authState.user?.full_name || "",
      email: authState.user?.email || "",
      job_title: authState.user?.job_title || "",
      error: "",
      success: ""
    }));
  }, [authState.user]);

  async function loadHistory() {
    setHistoryState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await apiFetch("/api/history?limit=50");
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to load history");
      }
      setHistoryState({ loading: false, error: "", records: data.records || [] });
      void loadReportsSummary();
    } catch (historyError) {
      setHistoryState({ loading: false, error: historyError.message, records: [] });
    }
  }

  async function loadJobs() {
    if (!authState.token) {
      setJobsState({ loading: false, error: "", jobs: [] });
      return;
    }
    setJobsState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await apiFetch("/api/jobs?limit=20");
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to load jobs");
      }
      setJobsState({ loading: false, error: "", jobs: data.jobs || [] });
    } catch (jobsError) {
      setJobsState({ loading: false, error: jobsError.message, jobs: [] });
    }
  }

  async function loadAdminUsers() {
    setAdminState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await apiFetch("/api/admin/users");
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to load users");
      }
      setAdminState({ loading: false, error: "", users: data.users || [], action: "" });
    } catch (adminError) {
      setAdminState({ loading: false, error: adminError.message, users: [], action: "" });
    }
  }

  async function loadReportsSummary() {
    setReportsState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await apiFetch("/api/reports/summary?limit=50");
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to load report summary");
      }
      let archive = [];
      let archiveError = "";
      if (authState.user?.role === "admin") {
        const archiveResponse = await apiFetch("/api/reports/archive?limit=8");
        const archiveData = await archiveResponse.json();
        archive = archiveResponse.ok ? archiveData.reports || [] : [];
        archiveError = archiveResponse.ok ? "" : archiveData.detail || "";
      }
      setReportsState({
        loading: false,
        error: archiveError,
        payload: data,
        archive
      });
    } catch (reportError) {
      setReportsState({ loading: false, error: reportError.message, payload: null, archive: [] });
    }
  }

  async function handleGenerateReport(format) {
    setReportAction({ loading: true, format, error: "", success: "" });
    try {
      const response = await apiFetch(`/api/reports/export?format=${format}`);
      const text = await response.text();
      if (!response.ok) {
        let message = "Unable to generate report";
        try {
          const payload = JSON.parse(text);
          message = payload.detail || message;
        } catch {
          message = text || message;
        }
        throw new Error(message);
      }

      const blob = new Blob([text], {
        type:
          format === "csv"
            ? "text/csv;charset=utf-8"
            : format === "md"
              ? "text/markdown;charset=utf-8"
              : "application/json;charset=utf-8"
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      link.href = url;
      link.download = `secureshield-report-${timestamp}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      await loadReportsSummary();
      setReportAction({
        loading: false,
        format: "",
        error: "",
        success: `${format.toUpperCase()} report downloaded and archived.`
      });
    } catch (reportError) {
      setReportAction({
        loading: false,
        format: "",
        error: reportError.message,
        success: ""
      });
    }
  }

  async function loadRecord(recordId) {
    setScanDetailState({ loading: true, error: "", record: null });
    try {
      const response = await apiFetch(`/api/history/${recordId}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to load scan detail");
      }
      setScanDetailState({ loading: false, error: "", record: data });
    } catch (recordError) {
      setScanDetailState({ loading: false, error: recordError.message, record: null });
    }
  }

  async function handleScan(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setScanProgress({
      active: true,
      phase: "Connecting to live scan channel...",
      module: "",
      percent: 8,
      events: ["Connecting to scan socket"],
      error: "",
      completed: false
    });

    try {
      const data = await runScanWithProgress(image, sourcePath, setScanProgress, apiFetch, authState.token);
      setScanResult(data);
      setLatestRecordDetail({ id: data.saved_record?.id, result: data, ...data.saved_record });
      await loadHistory();
      await loadJobs();
      setScanProgress((current) => ({
        ...current,
        active: false,
        completed: true,
        phase: "Scan completed",
        percent: 100
      }));
    } catch (scanError) {
      setError(scanError.message);
      setScanResult(null);
      setScanProgress((current) => ({
        ...current,
        active: false,
        completed: false,
        error: scanError.message,
        phase: "Scan failed"
      }));
    } finally {
      setLoading(false);
    }
  }

  async function handleAuthSubmit(event) {
    event.preventDefault();
    setAuthForm((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await apiFetch(authForm.mode === "register" ? "/api/auth/register" : "/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          username: authForm.username,
          password: authForm.password
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Authentication failed");
      }
      const nextAuth = {
        token: data.token,
        user: data.user
      };
      setAuthState(nextAuth);
      storeAuth(nextAuth);
      setAuthForm((current) => ({ ...current, loading: false, error: "", password: "" }));
      setRoute({ name: "dashboard" });
      window.history.pushState({}, "", "/");
    } catch (authError) {
      setAuthForm((current) => ({ ...current, loading: false, error: authError.message }));
    }
  }

  async function handleProfileSubmit(event) {
    event.preventDefault();
    setProfileForm((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const response = await apiFetch("/api/auth/profile", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          full_name: profileForm.full_name,
          email: profileForm.email,
          job_title: profileForm.job_title
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Profile update failed");
      }
      const nextAuth = { token: data.token, user: data.user };
      setAuthState(nextAuth);
      storeAuth(nextAuth);
      setProfileForm((current) => ({ ...current, loading: false, error: "", success: "Profile updated." }));
    } catch (profileError) {
      setProfileForm((current) => ({ ...current, loading: false, error: profileError.message, success: "" }));
    }
  }

  async function handlePasswordSubmit(event) {
    event.preventDefault();
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setPasswordForm((current) => ({ ...current, error: "New password and confirmation do not match.", success: "" }));
      return;
    }
    setPasswordForm((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const response = await apiFetch("/api/auth/password", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          current_password: passwordForm.current_password,
          new_password: passwordForm.new_password
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Password update failed");
      }
      const nextAuth = { token: data.token, user: data.user };
      setAuthState(nextAuth);
      storeAuth(nextAuth);
      setPasswordForm({
        current_password: "",
        new_password: "",
        confirm_password: "",
        loading: false,
        error: "",
        success: "Password changed."
      });
    } catch (passwordError) {
      setPasswordForm((current) => ({ ...current, loading: false, error: passwordError.message, success: "" }));
    }
  }

  async function handleAdminCreateUser(event) {
    event.preventDefault();
    setAdminUserForm((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const response = await apiFetch("/api/admin/users", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          username: adminUserForm.username,
          password: adminUserForm.password,
          role: adminUserForm.role,
          full_name: adminUserForm.full_name,
          email: adminUserForm.email,
          job_title: adminUserForm.job_title,
          is_active: true
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to create user");
      }
      setAdminUserForm({
        username: "",
        password: "",
        role: "analyst",
        full_name: "",
        email: "",
        job_title: "",
        loading: false,
        error: "",
        success: `Created ${data.user.username}.`
      });
      await loadAdminUsers();
    } catch (adminError) {
      setAdminUserForm((current) => ({ ...current, loading: false, error: adminError.message, success: "" }));
    }
  }

  async function handleAdminUserUpdate(userId, updates) {
    setAdminState((current) => ({ ...current, action: `${userId}`, error: "" }));
    try {
      const response = await apiFetch(`/api/admin/users/${userId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(updates)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to update user");
      }
      setAdminState((current) => ({
        ...current,
        action: "",
        users: current.users.map((item) => (item.id === userId ? data.user : item))
      }));
    } catch (adminError) {
      setAdminState((current) => ({ ...current, action: "", error: adminError.message }));
    }
  }

  async function handleAdminUserDelete(userId) {
    setAdminState((current) => ({ ...current, action: `${userId}`, error: "" }));
    try {
      const response = await apiFetch(`/api/admin/users/${userId}`, {
        method: "DELETE"
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to delete user");
      }
      setAdminState((current) => ({
        ...current,
        action: "",
        users: current.users.filter((item) => item.id !== userId)
      }));
      await loadHistory();
      await loadJobs();
    } catch (adminError) {
      setAdminState((current) => ({ ...current, action: "", error: adminError.message }));
    }
  }

  function handleLogout() {
    setAuthState({ token: "", user: null });
    storeAuth({ token: "", user: null });
    setLatestRecordDetail(null);
    setScanResult(null);
    setPasswordForm({
      current_password: "",
      new_password: "",
      confirm_password: "",
      loading: false,
      error: "",
      success: ""
    });
  }

  function openAuthPage(mode = "login") {
    setAuthForm((current) => ({
      ...current,
      mode,
      error: ""
    }));
    navigate("/auth");
  }

  function navigate(path) {
    if (!path) {
      return;
    }

    if (path.startsWith("#")) {
      const nextPath = `/${path}`;
      window.history.pushState({}, "", nextPath);
      startRouteTransition(() => setRoute({ name: "dashboard" }));
      queueHashScroll(path);
      return;
    }

    window.history.pushState({}, "", path);
    const nextRoute = readRoute();
    startRouteTransition(() => setRoute(nextRoute));
    setNotificationsOpen(false);

    const hashIndex = path.indexOf("#");
    if (hashIndex >= 0) {
      queueHashScroll(path.slice(hashIndex));
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function closeSidebarOnSmallScreen() {
    if (window.innerWidth <= 1180) {
      setSidebarOpen(false);
    }
  }

  function focusQuickScan(target = "image") {
    navigate("#quick-scan");
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        const field = target === "source" ? sourcePathInputRef.current : imageInputRef.current;
        if (field) {
          field.focus();
          field.select?.();
        }
      });
    });
  }

  function handleSidebarItemClick(item) {
    if (item.type === "route") {
      navigate(item.path);
      closeSidebarOnSmallScreen();
      return;
    }

    if (item.label === "Quick Scan") {
      focusQuickScan("image");
      closeSidebarOnSmallScreen();
      return;
    }

    if (item.label === "Image Scan") {
      setImage(DEFAULT_IMAGE);
      focusQuickScan("image");
      closeSidebarOnSmallScreen();
      return;
    }

    if (item.label === "Host Scan") {
      setSourcePath("/host/workload");
      focusQuickScan("source");
      closeSidebarOnSmallScreen();
      return;
    }

    if (item.label === "Registry Scan") {
      setImage("ghcr.io/example/app:latest");
      focusQuickScan("image");
      closeSidebarOnSmallScreen();
      return;
    }

    if (item.label === "K8s Cluster Scan") {
      setImage("registry.k8s.io/pause:3.9");
      focusQuickScan("image");
      closeSidebarOnSmallScreen();
      return;
    }

    navigate(item.path);
    closeSidebarOnSmallScreen();
  }

  function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (authState.token) {
      headers.set("Authorization", `Bearer ${authState.token}`);
    }
    return fetch(url, { ...options, headers });
  }

  async function handleAskAI(issue) {
    if (aiState.loading) {
      return;
    }

    setAiState({
      open: true,
      loading: true,
      error: "",
      response: null,
      selectedIssue: issue
    });

    try {
      const response = await apiFetch("/api/ai/remediate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          image: resolveIssueImage(issue, scanDetailState.record, latestRecord, latestRecordDetail, dashboardResult),
          finding: issue
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "AI remediation request failed");
      }
      setAiState({
        open: true,
        loading: false,
        error: "",
        response: data.guidance,
        selectedIssue: issue
      });
    } catch (aiError) {
      setAiState({
        open: true,
        loading: false,
        error: aiError.message,
        response: null,
        selectedIssue: issue
      });
    }
  }

  function closeAiModal() {
    setAiState({
      open: false,
      loading: false,
      error: "",
      response: null,
      selectedIssue: null
    });
  }

  function openChatModal(issue) {
    setChatModal({
      open: true,
      loading: false,
      error: "",
      selectedIssue: issue,
      messages: [
        {
          role: "assistant",
          text: "Ask how to fix this finding."
        }
      ],
      input: `How do I fix ${issue.id}?`
    });
  }

  function closeChatModal() {
    setChatModal({
      open: false,
      loading: false,
      error: "",
      selectedIssue: null,
      messages: [],
      input: ""
    });
  }

  function openDashboardModal(type, title) {
    setDashboardModal({
      open: true,
      type,
      title
    });
  }

  function closeDashboardModal() {
    setDashboardModal({
      open: false,
      type: "",
      title: ""
    });
  }

  function toggleNotifications() {
    setNotificationsOpen((current) => !current);
  }

  async function sendChatMessage() {
    if (!chatModal.selectedIssue || !chatModal.input.trim() || chatModal.loading) {
      return;
    }

    const question = chatModal.input.trim();
    const nextMessages = [...chatModal.messages, { role: "user", text: question }];
    setChatModal((current) => ({
      ...current,
      loading: true,
      error: "",
      messages: nextMessages,
      input: ""
    }));

    try {
      const response = await apiFetch("/api/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          image: resolveIssueImage(
            chatModal.selectedIssue,
            scanDetailState.record,
            latestRecord,
            latestRecordDetail,
            dashboardResult
          ),
          finding: chatModal.selectedIssue,
          question,
          history: nextMessages.map((message) => ({
            role: message.role,
            text: message.text
          }))
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "AI chat request failed");
      }
      setChatModal((current) => ({
        ...current,
        loading: false,
        error: "",
        messages: [
          ...nextMessages,
          {
            role: "assistant",
            text: data.response.answer,
            disclaimer: data.response.disclaimer
          }
        ]
      }));
    } catch (chatError) {
      setChatModal((current) => ({
        ...current,
        loading: false,
        error: chatError.message,
        messages: nextMessages
      }));
    }
  }

  async function sendFloatingChatMessage(questionOverride = "") {
    const question = (questionOverride || floatingChat.input).trim();
    if (!question || floatingChat.loading) {
      return;
    }

    const nextMessages = [...floatingChat.messages, { role: "user", text: question }];
    const latestIssue = latestIssues[0] || {};
    const contextFinding = {
      id: latestIssue.id || "SECURESHIELD_ASSISTANT",
      module: latestIssue.module || "general",
      severity: latestIssue.severity || "INFO",
      title: latestIssue.title || "General SecureShield assistant context",
      target: latestIssue.target || latestRecord?.target || dashboardResult?.image || "current workspace",
      summary: latestSummary,
      metadata: {
        latest_record_id: latestRecord?.id || null,
        security_score: dashboardResult?.security_score ?? latestRecord?.security_score ?? null,
        total_findings: latestSummary.total ?? 0,
        scan_count: historyState.records.length
      }
    };

    setFloatingChat((current) => ({
      ...current,
      loading: true,
      error: "",
      messages: nextMessages,
      input: ""
    }));

    try {
      const response = await apiFetch("/api/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          image: latestRecord?.target || dashboardResult?.image || null,
          finding: contextFinding,
          question,
          history: nextMessages.map((message) => ({
            role: message.role,
            text: message.text
          }))
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "AI chat request failed");
      }
      setFloatingChat((current) => ({
        ...current,
        loading: false,
        error: "",
        messages: [
          ...nextMessages,
          {
            role: "assistant",
            text: data.response.answer,
            disclaimer: data.response.disclaimer
          }
        ]
      }));
    } catch (chatError) {
      setFloatingChat((current) => ({
        ...current,
        loading: false,
        error: chatError.message,
        messages: nextMessages
      }));
    }
  }

  const dashboardResult = scanResult || latestRecordDetail?.result || null;
  const latestSummary = dashboardResult?.summary || zeroSummary();
  const latestIssues = dashboardResult?.issues || [];
  const filteredIssues = useMemo(() => {
    const issues = scanDetailState.record?.result?.issues || [];
    return issues.filter((issue) => {
      const severityMatch =
        filters.severity === "ALL" || (issue.severity || "UNKNOWN").toUpperCase() === filters.severity;
      const moduleMatch =
        filters.module === "ALL" || (issue.module || "-").toLowerCase() === filters.module.toLowerCase();
      const searchValue = filters.search.trim().toLowerCase();
      const haystack = [issue.id, issue.title, issue.target, issue.module].join(" ").toLowerCase();
      return severityMatch && moduleMatch && (!searchValue || haystack.includes(searchValue));
    });
  }, [filters, scanDetailState.record]);

  const latestRecord = historyState.records[0] || latestRecordDetail;
  const activeView = NAV_ITEMS.find((item) => item.key === route.name) || NAV_ITEMS[0];
  const currentUser = authState.user?.username || "Analyst";
  const currentDisplayName = authState.user?.full_name || currentUser;
  const currentJobTitle = authState.user?.job_title || "Security Engineer";
  const dashboardBadges = {
    vulnerabilities: latestSummary.critical ?? latestSummary.total ?? 0,
    cis: `${calculateCisScore(dashboardResult)}%`,
    secrets: (dashboardResult?.modules?.secrets?.findings || []).length || latestSummary.high || 0
  };

  if (route.name === "auth") {
    return (
      <AuthPage
        authState={authState}
        authForm={authForm}
        onAuthChange={setAuthForm}
        onAuthSubmit={handleAuthSubmit}
        profileForm={profileForm}
        onProfileChange={setProfileForm}
        onProfileSubmit={handleProfileSubmit}
        passwordForm={passwordForm}
        onPasswordChange={setPasswordForm}
        onPasswordSubmit={handlePasswordSubmit}
        onLogout={handleLogout}
        onNavigate={navigate}
      />
    );
  }

  return (
    <div className={`app-shell ${sidebarOpen ? "sidebar-open" : "sidebar-closed"}`}>
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <button className="sidebar-overlay" type="button" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />

      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-header">
            <div className="brand-mark">
              <img src={brandLogo} alt="SecureShield" />
            </div>
            <div>
              <h1>SecureShield</h1>
              <p className="sidebar-copy">Container Security Platform</p>
            </div>
          </div>
        </div>

        <nav className="sidebar-groups">
          {SIDEBAR_GROUPS.map((group) => (
            <div key={group.label} className="sidebar-group">
              <p className="sidebar-group-label">{group.label}</p>
              <div className="nav-links">
                {group.items.map((item) => {
                  if (item.adminOnly && authState.user?.role !== "admin") {
                    return null;
                  }
                  const isRoute = item.type === "route";
                  const isActive = isRoute && route.name === item.key;
                  return (
                    <button
                      key={`${group.label}-${item.label}`}
                      className={`nav-link nav-link-compact ${isActive ? "nav-link-active" : ""}`}
                      onClick={() => handleSidebarItemClick(item)}
                      type="button"
                    >
                      <span className={`nav-icon nav-icon-${item.icon || "dot"}`}>{navGlyph(item.icon)}</span>
                      <div className="nav-copy">
                        <strong>{item.label}</strong>
                      </div>
                      {item.badge ? <span className="nav-badge">{item.badge}</span> : null}
                      {!item.badge && item.label === "Vulnerabilities" ? <span className="nav-metric nav-metric-critical">{dashboardBadges.vulnerabilities}</span> : null}
                      {!item.badge && item.label === "CIS Benchmark" ? <span className="nav-metric nav-metric-success">{dashboardBadges.cis}</span> : null}
                      {!item.badge && item.label === "Secrets Detection" ? <span className="nav-metric nav-metric-warning">{dashboardBadges.secrets}</span> : null}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <section className="sidebar-panel muted-panel">
          <div className="sidebar-version">
            <span>SecureShield v1.0.0</span>
            <span className="sidebar-status-dot" />
          </div>
        </section>
      </aside>

      <main className="content-shell">
        {route.name === "dashboard" ? (
          <header className="topbar">
            <div className="topbar-row">
              <button
                className="menu-button"
                type="button"
                aria-label={sidebarOpen ? "Close navigation" : "Open navigation"}
                aria-expanded={sidebarOpen}
                onClick={() => setSidebarOpen((current) => !current)}
              >
                <span />
                <span />
                <span />
              </button>
              <div className="topbar-search">
                <span className="topbar-search-logo" aria-hidden="true">
                  <img src={brandLogo} alt="" />
                </span>
                <input
                  value={image}
                  onChange={(event) => setImage(event.target.value)}
                  placeholder="Search images, containers, vulnerabilities..."
                />
                <span className="search-shortcut">⌘ K</span>
              </div>
              <div className="topbar-auth">
                <button className="icon-button" type="button" onClick={() => navigate("/history")}>
                  &gt;_
                </button>
                <div className="notification-wrap">
                  <button className="icon-button notification-trigger" type="button" onClick={toggleNotifications} aria-label="Open notifications">
                    🔔
                  </button>
                  {notificationsOpen ? (
                    <NotificationsPanel
                      latestRecord={latestRecord}
                      reportsState={reportsState}
                      jobsState={jobsState}
                      onNavigate={navigate}
                    />
                  ) : null}
                </div>
                {authState.user ? (
                  <>
                    <button className="topbar-profile" type="button" onClick={() => navigate("/auth")}>
                      <span className="profile-avatar">{currentUser.slice(0, 1).toUpperCase()}</span>
                      <span>
                        <strong>{currentDisplayName}</strong>
                        <small>{currentJobTitle}</small>
                      </span>
                    </button>
                    <button className="topbar-auth-action topbar-auth-logout" type="button" onClick={handleLogout}>
                      Logout
                    </button>
                  </>
                ) : (
                  <button className="topbar-auth-action topbar-auth-primary" type="button" onClick={() => openAuthPage("login")}>
                    Login
                  </button>
                )}
              </div>
            </div>
            <div className="topbar-main">
              <div className="topbar-copy">
                <p className="eyebrow">{activeView.label}</p>
                <h2>{`Welcome back, ${currentUser}!`}</h2>
                <p className="hero-copy">Here's what's happening with your container security.</p>
              </div>

              <div className="topbar-banner">
                <div className="banner-grid" />
                <div className="banner-shield">
                  <div className="banner-shield-core" />
                </div>
              </div>

              <div className="topbar-stack">
                <section className="scanner-card">
                  <div className="panel-heading compact">
                    <div>
                      <p className="eyebrow">Scanner Engine</p>
                      <h3>All systems operational</h3>
                    </div>
                    <span className="scanner-status-dot" />
                  </div>
                  <p className="muted-copy">Trivy, CIS, runtime, secrets, and supply chain checks are ready.</p>
                  <div className="scanner-meta">
                    <span>{historyState.loading ? "Refreshing scan cache" : `${historyState.records.length} assets tracked`}</span>
                    <span>{latestRecord?.created_at ? `Updated ${formatDate(latestRecord.created_at)}` : "Awaiting baseline scan"}</span>
                  </div>
                </section>

                <form className="scan-form" id="quick-scan" onSubmit={handleScan}>
                  <div className="scan-form-head">
                    <strong>New Scan</strong>
                    <span>⌄</span>
                  </div>
                  <label htmlFor="source-path" className="panel-label">
                    Quick Scan
                  </label>
                  <div className="form-row form-row-stacked">
                    <input id="image" ref={imageInputRef} value={image} onChange={(event) => setImage(event.target.value)} placeholder="e.g. nginx:latest" />
                    <button type="submit" disabled={loading}>
                      {loading ? "Scanning..." : "Run"}
                    </button>
                  </div>
                  <div className="form-row">
                    <input
                      id="source-path"
                      ref={sourcePathInputRef}
                      value={sourcePath}
                      onChange={(event) => setSourcePath(event.target.value)}
                      placeholder="Optional source path for secrets scan"
                    />
                  </div>
                  <div className="quick-actions">
                    {QUICK_IMAGES.map((item) => (
                      <button key={item} type="button" className="quick-chip" onClick={() => setImage(item)}>
                        {item}
                      </button>
                    ))}
                  </div>
                </form>
              </div>
            </div>
          </header>
        ) : null}

        {loading || scanProgress.completed || scanProgress.error ? <ScanProgressPanel progress={scanProgress} /> : null}

        {error ? <div className="error-box">{error}</div> : null}

        {route.name === "dashboard" ? (
          <DashboardPage
            summary={latestSummary}
            scanResult={dashboardResult}
            historyState={historyState}
            latestIssues={latestIssues}
            onNavigate={navigate}
            onOpenLatestIssue={() => navigate(latestRecord ? `/scan/${latestRecord.id}` : "/history")}
            onOpenDashboardModal={openDashboardModal}
          />
        ) : null}

        {route.name === "history" ? <HistoryPage historyState={historyState} onNavigate={navigate} /> : null}

        {route.name === "detail" ? (
          <DetailPage
            detailState={scanDetailState}
            filters={filters}
            onFilterChange={setFilters}
            filteredIssues={filteredIssues}
            aiState={aiState}
            onAskAI={handleAskAI}
            chatModal={chatModal}
            onOpenChat={openChatModal}
          />
        ) : null}

        {route.name === "reports" ? (
          <ReportsPage
            historyState={historyState}
            reportsState={reportsState}
            latestResult={dashboardResult}
            onNavigate={navigate}
            reportAction={reportAction}
            onGenerateReport={handleGenerateReport}
          />
        ) : null}

        {isAnalyzeRoute(route.name) ? (
          <AnalyzeModulePage
            routeName={route.name}
            scanResult={dashboardResult}
            historyState={historyState}
            latestIssues={latestIssues}
            aiState={aiState}
            chatModal={chatModal}
            onAskAI={handleAskAI}
            onOpenChat={openChatModal}
            onNavigate={navigate}
          />
        ) : null}

        {route.name === "export" ? (
          <ExportCenterPage
            reportsState={reportsState}
            reportAction={reportAction}
            onGenerateReport={handleGenerateReport}
            onNavigate={navigate}
          />
        ) : null}

        {route.name === "scheduled" ? (
          <ScheduledScansPage
            jobsState={jobsState}
            historyState={historyState}
            onNavigate={navigate}
            onRefresh={loadJobs}
          />
        ) : null}

        {route.name === "admin" ? (
          <AdminPage
            authState={authState}
            adminState={adminState}
            adminUserForm={adminUserForm}
            historyState={historyState}
            jobsState={jobsState}
            onFormChange={setAdminUserForm}
            onCreateUser={handleAdminCreateUser}
            onUpdateUser={handleAdminUserUpdate}
            onDeleteUser={handleAdminUserDelete}
            onRefresh={() => {
              void loadAdminUsers();
              void loadHistory();
              void loadJobs();
            }}
            onNavigate={navigate}
          />
        ) : null}

        {route.name === "settings" ? (
          <SettingsPage authState={authState} jobsState={jobsState} onNavigate={navigate} />
        ) : null}

      </main>

      {chatModal.open ? (
        <AIChatModal
          chatModal={chatModal}
          onClose={closeChatModal}
          onInputChange={(value) => setChatModal((current) => ({ ...current, input: value }))}
          onSend={sendChatMessage}
        />
      ) : null}

      {aiState.open ? <AIRemediationModal aiState={aiState} onClose={closeAiModal} /> : null}

      {dashboardModal.open ? (
        <DashboardDetailsModal
          modal={dashboardModal}
          onClose={closeDashboardModal}
          historyState={historyState}
          activityItems={buildActivityFeed({
            latestRecord,
            latestIssues,
            moduleCards: buildModuleCards(dashboardResult),
            summary: latestSummary
          })}
          issues={latestIssues}
          onNavigate={navigate}
          onAskAI={handleAskAI}
          onOpenChat={openChatModal}
          aiLoading={aiState.loading}
          chatLoading={chatModal.loading}
        />
      ) : null}

      <FloatingAIChat
        chat={floatingChat}
        onToggle={() => setFloatingChat((current) => ({ ...current, open: !current.open, error: "" }))}
        onClose={() => setFloatingChat((current) => ({ ...current, open: false, error: "" }))}
        onInputChange={(value) => setFloatingChat((current) => ({ ...current, input: value }))}
        onSend={sendFloatingChatMessage}
      />
    </div>
  );
}

function DashboardPage({
  summary,
  scanResult,
  historyState,
  latestIssues,
  onNavigate,
  onOpenLatestIssue,
  onOpenDashboardModal
}) {
  const latestRecord = historyState.records[0];
  const severityData = [
    { label: "Critical", key: "critical", value: summary.critical ?? 0, tone: "critical" },
    { label: "High", key: "high", value: summary.high ?? 0, tone: "high" },
    { label: "Medium", key: "medium", value: summary.medium ?? 0, tone: "medium" },
    { label: "Low", key: "low", value: summary.low ?? 0, tone: "low" }
  ];
  const moduleCards = buildModuleCards(scanResult);
  const recentRecords = historyState.records.slice(0, 5);
  const vulnerabilityTrend = recentRecords.length ? [...recentRecords].reverse() : [];
  const criticalCount = summary.critical ?? 0;
  const highCount = summary.high ?? 0;
  const mediumCount = summary.medium ?? 0;
  const lowCount = summary.low ?? 0;
  const assetsScanned = historyState.records.reduce((count, record) => count + (record.normalized_counts?.images ?? 1), 0);
  const secretsFound = (scanResult?.modules?.secrets?.findings || []).length;
  const topIssues = latestIssues
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 5);
  const cisSummary = buildCisSummary(scanResult);
  const cisScore = calculateCisScore(scanResult);
  const postureMetrics = buildPostureMetrics({ scanResult, summary });
  const statCards = [
    { label: "Total Scans", value: historyState.records.length, change: `${recentRecords.length} this week`, tone: "info", icon: "◎" },
    { label: "Critical Findings", value: criticalCount, change: `${Math.max(highCount, 0)} this week`, tone: "critical", icon: "⛨" },
    { label: "High Severity", value: highCount, change: `${Math.max(mediumCount, 0)} this week`, tone: "high", icon: "≈" },
    { label: "CIS Score", value: `${cisScore}%`, change: `${cisSummary.passed}/${Math.max(cisSummary.passed + cisSummary.failed + cisSummary.warning + cisSummary.notRun, 0)} passed`, tone: "info", icon: "◔" },
    { label: "Assets Scanned", value: assetsScanned, change: `${recentRecords.length * 24 || 0} this week`, tone: "low", icon: "◈" },
    { label: "Secrets Found", value: secretsFound, change: `${Math.max(lowCount, 0)} this week`, tone: "medium", icon: "⌘" }
  ];
  const riskScore = Number(scanResult?.security_score ?? latestRecord?.security_score ?? 0);
  const activityItems = buildActivityFeed({ latestRecord, latestIssues, moduleCards, summary });

  return (
    <div className="dashboard-layout">
      <MetricMarquee cards={statCards} />

      <section className="panel dashboard-risk-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Risk Overview</p>
            <h3>Current posture</h3>
          </div>
        </div>
        <div className="risk-overview-layout">
          <GaugeCard score={riskScore} />
          <div className="risk-breakdown-side">
            <div className="risk-breakdown-list">
              {severityData.map((item) => (
                <div key={item.key} className="risk-breakdown-item">
                  <span className={`risk-swatch risk-swatch-${item.tone}`} />
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                  <small>{summary.total ? `${((item.value / summary.total) * 100).toFixed(1)}%` : "0%"}</small>
                </div>
              ))}
            </div>
          </div>
        </div>
        <p className="risk-footer-copy">Risk score is calculated based on severity and CVSS score.</p>
      </section>

      <section className="panel dashboard-chart-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Vulnerabilities Over Time</p>
            <h3>Last 7 Days</h3>
          </div>
          <span>Last 7 Days</span>
        </div>
        <TrendChart records={vulnerabilityTrend} />
      </section>

      <section className="panel dashboard-list-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Recent Scans</p>
            <h3>Saved records</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onOpenDashboardModal("recent_scans", "Recent Scans")}>
            View all
          </button>
        </div>
        <RecentScanList records={recentRecords} onNavigate={onNavigate} />
      </section>

      <section className="panel dashboard-feed-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Activity Feed</p>
            <h3>Latest events</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onOpenDashboardModal("activity_feed", "Activity Feed")}>
            View all
          </button>
        </div>
        <ActivityFeed items={activityItems} />
      </section>

      <section className="panel dashboard-vuln-card" id="latest-issues">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Top Vulnerabilities</p>
            <h3>Priority findings</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onOpenDashboardModal("top_vulnerabilities", "Top Vulnerabilities")}>
            View all
          </button>
        </div>
        <TopVulnerabilitiesList issues={topIssues} onOpenLatestIssue={onOpenLatestIssue} />
      </section>

      <section className="panel dashboard-cis-card" id="cis-benchmark">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">CIS Benchmark Progress</p>
            <h3>Compliance score</h3>
          </div>
        </div>
        <CisBenchmarkCard summary={cisSummary} score={cisScore} onNavigate={onNavigate} />
      </section>

      <section className="panel dashboard-posture-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Security Posture</p>
            <h3>Module balance</h3>
          </div>
        </div>
        <SecurityPostureCard metrics={postureMetrics} />
      </section>

    </div>
  );
}

function HistoryPage({ historyState, onNavigate }) {
  return (
    <section className="panel page-section">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">History</p>
          <h3>Saved scan records</h3>
          <p className="muted-copy">Saved scans, ready to review.</p>
        </div>
      </div>
      {historyState.error ? <div className="error-box">{historyState.error}</div> : null}
      <HistoryTable records={historyState.records} loading={historyState.loading} onNavigate={onNavigate} />
    </section>
  );
}

function DetailPage({ detailState, filters, onFilterChange, filteredIssues, aiState, onAskAI, chatModal, onOpenChat }) {
  const record = detailState.record;
  const result = record?.result;
  const summary = result?.summary || zeroSummary();
  const activeFilters = [
    filters.severity !== "ALL" ? `Severity: ${filters.severity}` : null,
    filters.module !== "ALL" ? `Module: ${filters.module}` : null,
    filters.search.trim() ? `Search: ${filters.search.trim()}` : null
  ].filter(Boolean);

  return (
    <div className="page-grid">
      <section className="hero-panel two-column-span">
        <div className="hero-copy-block">
          <p className="eyebrow">Scan Detail</p>
          <h3>{record ? record.target : "Loading scan detail..."}</h3>
          <p className="hero-copy">Filter findings and fix faster.</p>
        </div>
        <ScoreRing score={result?.security_score} label={`Scan ID ${record?.id ?? "--"}`} />
      </section>

      <section className="status-rail two-column-span">
        <StatusTile label="Target" value={record?.target || "--"} />
        <StatusTile label="Scan Type" value={record?.scan_type || "--"} />
        <StatusTile label="Created" value={record?.created_at ? formatDate(record.created_at) : "--"} />
        <StatusTile label="Filtered Results" value={filteredIssues.length} />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Stored Entities</p>
            <h3>Normalized scan data</h3>
          </div>
        </div>
        <div className="entity-grid">
          <MetricBlock label="Images" value={record?.normalized_counts?.images ?? 0} />
          <MetricBlock label="Vulnerabilities" value={record?.normalized_counts?.vulnerabilities ?? 0} />
          <MetricBlock label="Compliance Results" value={record?.normalized_counts?.compliance_results ?? 0} />
          <MetricBlock label="Secret Findings" value={record?.normalized_counts?.secret_findings ?? 0} />
          <MetricBlock label="Runtime Events" value={record?.normalized_counts?.runtime_events ?? 0} />
          <MetricBlock label="Saved Record" value={record?.id ?? "--"} />
        </div>
      </section>

      {detailState.error ? <div className="error-box two-column-span">{detailState.error}</div> : null}

      <section className="cards two-column-span">
        <SummaryCard label="Critical" value={summary.critical ?? 0} tone="critical" />
        <SummaryCard label="High" value={summary.high ?? 0} tone="high" />
        <SummaryCard label="Medium" value={summary.medium ?? 0} tone="medium" />
        <SummaryCard label="Low" value={summary.low ?? 0} tone="low" />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Findings Filter</p>
            <h3>Narrow the view</h3>
          </div>
        </div>
        <div className="filters-grid">
          <select value={filters.severity} onChange={(event) => onFilterChange((current) => ({ ...current, severity: event.target.value }))}>
            {FILTER_SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <select value={filters.module} onChange={(event) => onFilterChange((current) => ({ ...current, module: event.target.value }))}>
            {FILTER_MODULES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <input
            value={filters.search}
            onChange={(event) => onFilterChange((current) => ({ ...current, search: event.target.value }))}
            placeholder="Search by CVE, module, target..."
          />
        </div>
        {activeFilters.length ? (
          <div className="filter-chip-row">
            {activeFilters.map((item) => (
              <span key={item} className="table-chip">
                {item}
              </span>
            ))}
          </div>
        ) : (
          <p className="muted-copy filter-hint">Showing all findings.</p>
        )}
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Issues</p>
            <h3>Filtered findings</h3>
          </div>
          <span>{filteredIssues.length} items</span>
        </div>
        {detailState.loading ? (
          <div className="empty-state">Loading scan record...</div>
        ) : (
          <IssueTable
            issues={filteredIssues}
            onAskAI={onAskAI}
            onOpenChat={onOpenChat}
            aiLoading={aiState.loading}
            chatLoading={chatModal.loading}
          />
        )}
      </section>
    </div>
  );
}

function ReportsPage({ historyState, reportsState, latestResult, onNavigate, reportAction, onGenerateReport }) {
  const fullScans = historyState.records.filter((record) => record.scan_type === "full");
  const latestScore = latestResult?.security_score ?? historyState.records[0]?.security_score ?? "--";
  const reportSummary = reportsState.payload?.summary || null;
  const reportArchive = reportsState.archive || [];
  const aggregate = historyState.records.reduce(
    (acc, record) => {
      const summary = record.summary || {};
      acc.total += summary.total || 0;
      acc.critical += summary.critical || 0;
      acc.high += summary.high || 0;
      acc.medium += summary.medium || 0;
      acc.low += summary.low || 0;
      return acc;
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
  );

  return (
    <div className="page-grid">
      <section className="hero-panel two-column-span">
        <div className="hero-copy-block">
          <p className="eyebrow">Exposure Reports</p>
          <h3>Aggregate severity and recent image pressure</h3>
          <p className="hero-copy">Export and review saved scan data.</p>
        </div>
        <ScoreRing score={latestScore} label="Latest Score" />
      </section>

      <section className="cards two-column-span">
        <SummaryCard label="Critical" value={reportSummary?.critical ?? aggregate.critical} tone="critical" />
        <SummaryCard label="High" value={reportSummary?.high ?? aggregate.high} tone="high" />
        <SummaryCard label="Medium" value={reportSummary?.medium ?? aggregate.medium} tone="medium" />
        <SummaryCard label="Low" value={reportSummary?.low ?? aggregate.low} tone="low" />
      </section>

      <section className="status-rail two-column-span">
        <StatusTile label="Records" value={reportSummary?.total_records ?? historyState.records.length} />
        <StatusTile label="Full Scans" value={reportSummary?.scan_types?.full ?? fullScans.length} />
        <StatusTile label="Latest Target" value={historyState.records[0]?.target || "--"} />
        <StatusTile label="Total Findings" value={reportSummary?.total_findings ?? aggregate.total} />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Report API</p>
            <h3>Live aggregate summary</h3>
          </div>
          <span>{reportsState.loading ? "Refreshing..." : "Synced from /api/reports/summary"}</span>
        </div>
        {reportsState.error ? <div className="error-box">{reportsState.error}</div> : null}
        <div className="report-api-grid">
          <MetricBlock label="All Records" value={reportSummary?.total_records ?? "--"} />
          <MetricBlock label="All Findings" value={reportSummary?.total_findings ?? "--"} />
          <MetricBlock label="Full Scans" value={reportSummary?.scan_types?.full ?? 0} />
          <MetricBlock label="Runtime Scans" value={reportSummary?.scan_types?.runtime ?? 0} />
          <MetricBlock label="Secrets Scans" value={reportSummary?.scan_types?.secrets ?? 0} />
          <MetricBlock label="Supply Chain" value={reportSummary?.scan_types?.supply_chain ?? 0} />
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Snapshot</p>
            <h3>Saved scan summary</h3>
          </div>
        </div>
        <div className="report-grid">
          <MetricBlock label="Saved Scans" value={historyState.records.length} />
          <MetricBlock label="Full Scans" value={fullScans.length} />
          <MetricBlock label="Total Findings" value={aggregate.total} />
          <MetricBlock label="Latest Target" value={historyState.records[0]?.target || "--"} />
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Generate</p>
            <h3>Download a fresh report</h3>
          </div>
          <span>{reportAction.loading ? "Preparing file..." : "One click export"}</span>
        </div>
        <div className="report-action-panel">
          <p className="muted-copy">Download the current dataset. Exports are saved below.</p>
          <div className="report-download-actions">
            <button
              className="primary-button"
              type="button"
              onClick={() => onGenerateReport("json")}
              disabled={reportAction.loading}
            >
              {reportAction.loading && reportAction.format === "json" ? "Generating JSON..." : "Generate JSON Report"}
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => onGenerateReport("csv")}
              disabled={reportAction.loading}
            >
              {reportAction.loading && reportAction.format === "csv" ? "Generating CSV..." : "Generate CSV Report"}
            </button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => onGenerateReport("md")}
              disabled={reportAction.loading}
            >
              {reportAction.loading && reportAction.format === "md" ? "Generating Table..." : "Generate Table Report"}
            </button>
          </div>
          {reportAction.error ? <div className="error-box">{reportAction.error}</div> : null}
          {reportAction.success ? <div className="success-box">{reportAction.success}</div> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Distribution</p>
            <h3>Severity overview</h3>
          </div>
        </div>
        <SeverityChart
          items={[
            { label: "Critical", key: "critical", value: aggregate.critical, tone: "critical" },
            { label: "High", key: "high", value: aggregate.high, tone: "high" },
            { label: "Medium", key: "medium", value: aggregate.medium, tone: "medium" },
            { label: "Low", key: "low", value: aggregate.low, tone: "low" }
          ]}
        />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Recent Evidence</p>
            <h3>Image reports</h3>
          </div>
          <div className="inline-actions">
            <button className="text-button" type="button" onClick={() => onNavigate("/history")}>
              Open history
            </button>
          </div>
        </div>
        <HistoryTable records={historyState.records.slice(0, 10)} loading={historyState.loading} onNavigate={onNavigate} />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Archive</p>
            <h3>Generated report history</h3>
          </div>
          <span>{reportArchive.length} saved exports</span>
        </div>
        {!reportArchive.length ? (
          <div className="empty-state">No saved exports yet.</div>
        ) : (
          <div className="report-archive-list">
            {reportArchive.map((item) => (
              <article key={item.id} className="archive-card">
                <span className="table-chip">{item.format}</span>
                <strong>{item.report_type}</strong>
                <span className="muted-copy">Created {formatDate(item.created_at)}</span>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function AnalyzeModulePage({
  routeName,
  scanResult,
  historyState,
  latestIssues,
  aiState,
  chatModal,
  onAskAI,
  onOpenChat,
  onNavigate
}) {
  const config = analyzeConfig(routeName);
  const latestRecord = historyState.records[0];
  const moduleCards = useMemo(() => buildModuleCards(scanResult), [scanResult]);
  const moduleCard = useMemo(() => moduleCards.find((item) => item.key === config.cardKey), [config.cardKey, moduleCards]);
  const moduleIssues = useMemo(
    () => latestIssues.filter((issue) => config.issueModules.includes(String(issue.module || "").toLowerCase())),
    [config.issueModules, latestIssues]
  );
  const moduleChecks = useMemo(() => extractModuleRows(scanResult, config.moduleKey), [config.moduleKey, scanResult]);
  const summary = scanResult?.summary || zeroSummary();
  const evidenceCount = config.showIssues ? moduleIssues.length : moduleChecks.length;
  const failingChecks = useMemo(() => moduleChecks.filter((row) => statusTone(row.status) === "critical").length, [moduleChecks]);
  const moduleHealth = moduleCard?.status || (evidenceCount ? "Needs Review" : "Clean");
  const displayValue = useMemo(
    () =>
      analyzeDisplayValue(routeName, {
        scanResult,
        moduleCard,
        moduleIssues,
        moduleChecks
      }),
    [moduleCard, moduleChecks, moduleIssues, routeName, scanResult]
  );
  const healthScore = useMemo(
    () =>
      analyzeHealthScore(routeName, {
        scanResult,
        moduleCard,
        moduleIssues,
        moduleChecks
      }),
    [moduleCard, moduleChecks, moduleIssues, routeName, scanResult]
  );

  return (
    <div className="page-grid analyze-page">
      <section className={`hero-panel analyze-hero analyze-hero-${routeName} two-column-span`}>
        <div className="hero-copy-block">
          <p className="eyebrow">Analyze</p>
          <h3>{config.title}</h3>
          <p className="hero-copy">{config.description}</p>
          <div className="hero-badges">
            <span className="hero-badge">{latestRecord?.target || "No scan selected"}</span>
            <span className="hero-badge">{latestRecord?.created_at ? formatDate(latestRecord.created_at) : "Awaiting scan"}</span>
          </div>
        </div>
        <div className="analyze-hero-visual">
          <span>{config.icon}</span>
          <ScoreRing score={displayValue} label={config.scoreLabel} />
        </div>
      </section>

      <section className="analyze-tabs two-column-span" aria-label="Analyze pages">
        {analyzeNavItems().map((item) => (
          <button
            key={item.key}
            className={`analyze-tab ${routeName === item.key ? "analyze-tab-active" : ""}`}
            type="button"
            onClick={() => onNavigate(item.path)}
          >
            <span>{item.icon}</span>
            <strong>{item.label}</strong>
          </button>
        ))}
      </section>

      <section className="analyze-status-grid two-column-span">
        <SummaryCard label="Module Findings" value={moduleCard?.count ?? moduleIssues.length} tone={moduleCard?.tone || "info"} compact icon={config.icon} />
        <SummaryCard label="Evidence Rows" value={evidenceCount} tone="info" compact icon="☰" />
        <SummaryCard label="Failing Checks" value={failingChecks} tone={failingChecks ? "critical" : "low"} compact icon="!" />
        <SummaryCard label="Total Scans" value={historyState.records.length} tone="low" compact icon="◎" />
      </section>

      <section className="analyze-insight-grid two-column-span">
        <article className="panel analyze-summary-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Module State</p>
              <h3>{moduleHealth}</h3>
            </div>
            <span className={`badge badge-${moduleCard?.tone || "info"}`}>{config.title}</span>
          </div>
          <div className="analyze-health-meter">
            <div style={{ width: `${healthScore}%` }} />
          </div>
          <p className="muted-copy">{moduleCard?.description || config.description}</p>
          <div className="analyze-mini-metrics">
            <MetricBlock label="Critical" value={summary.critical ?? 0} />
            <MetricBlock label="High" value={summary.high ?? 0} />
            <MetricBlock label="Medium" value={summary.medium ?? 0} />
          </div>
        </article>

        {routeName === "cis" ? (
          <section className="panel analyze-cis-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">CIS Benchmark</p>
                <h3>Compliance progress</h3>
              </div>
            </div>
            <CisBenchmarkCard summary={buildCisSummary(scanResult)} score={healthScore} onNavigate={onNavigate} />
          </section>
        ) : (
          <article className="panel analyze-actions-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Workflow</p>
                <h3>Next review actions</h3>
              </div>
            </div>
            <div className="analyze-action-list">
              {config.actions.map((action) => (
                <span key={action}>{action}</span>
              ))}
            </div>
            <div className="inline-actions">
              <button className="primary-button" type="button" onClick={() => onNavigate(latestRecord ? `/scan/${latestRecord.id}` : "/history")}>
                Open latest scan
              </button>
              <button className="secondary-button" type="button" onClick={() => onNavigate("/reports")}>
                Open reports
              </button>
            </div>
          </article>
        )}
      </section>

      <section className="panel two-column-span analyze-evidence-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Evidence</p>
            <h3>{config.tableTitle}</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onNavigate(latestRecord ? `/scan/${latestRecord.id}` : "/history")}>
            Open latest scan
          </button>
        </div>
        {config.showIssues ? (
          <IssueTable
            issues={moduleIssues}
            onAskAI={onAskAI}
            onOpenChat={onOpenChat}
            aiLoading={aiState.loading}
            chatLoading={chatModal.loading}
          />
        ) : (
          <ModuleRowsTable rows={moduleChecks} emptyText={`No ${config.title.toLowerCase()} checks available yet.`} />
        )}
      </section>

      {!config.showIssues && moduleIssues.length ? (
        <section className="panel two-column-span">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Findings</p>
              <h3>Related normalized issues</h3>
            </div>
          </div>
          <IssueTable
            issues={moduleIssues}
            onAskAI={onAskAI}
            onOpenChat={onOpenChat}
            aiLoading={aiState.loading}
            chatLoading={chatModal.loading}
          />
        </section>
      ) : null}
    </div>
  );
}

function ModuleRowsTable({ rows, emptyText }) {
  if (!rows.length) {
    return <div className="empty-state">{emptyText}</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>ID</th>
            <th>Title</th>
            <th>Target</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={`${row.id || row.title}-${index}`}>
              <td>
                <span className={`badge badge-${statusTone(row.status)}`}>{row.status || "INFO"}</span>
              </td>
              <td>{row.id || row.check_id || "--"}</td>
              <td>{row.title || row.name || row.description || "--"}</td>
              <td className="table-target">{row.target || row.image || row.path || "--"}</td>
              <td className="table-target">{row.evidence || row.message || row.remediation || row.reason || "--"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExportCenterPage({ reportsState, reportAction, onGenerateReport, onNavigate }) {
  const reportArchive = reportsState.archive || [];
  const reportSummary = reportsState.payload?.summary || null;
  const exportOptions = [
    { label: "JSON", format: "json", description: "Structured report data for tools and dashboards.", enabled: true },
    { label: "CSV", format: "csv", description: "Spreadsheet-ready finding and scan evidence.", enabled: true },
    { label: "Table", format: "md", description: "Markdown table report for notes and tickets.", enabled: true },
    { label: "PDF", format: "", description: "Open report view before preparing PDF output.", enabled: false },
    { label: "SARIF", format: "", description: "Review report evidence before SARIF integration.", enabled: false }
  ];

  return (
    <div className="page-grid">
      <section className="hero-panel two-column-span">
        <div className="hero-copy-block">
          <p className="eyebrow">Export Center</p>
          <h3>Generate and download security reports</h3>
          <p className="hero-copy">Exports are handled here, separate from the dashboard.</p>
        </div>
        <ScoreRing score={reportSummary?.average_security_score ?? "--"} label="Report Score" />
      </section>

      <section className="status-rail two-column-span">
        <StatusTile label="Records" value={reportSummary?.total_records ?? "--"} />
        <StatusTile label="Findings" value={reportSummary?.total_findings ?? "--"} />
        <StatusTile label="Saved Exports" value={reportArchive.length} />
        <StatusTile label="State" value={reportsState.loading ? "Refreshing" : "Ready"} />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Downloads</p>
            <h3>Export formats</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onNavigate("/reports")}>
            Open reports
          </button>
        </div>
        <div className="export-format-grid">
          {exportOptions.map((item) => (
            <button
              key={item.label}
              className={`export-format-card ${item.enabled ? "" : "export-format-muted"}`}
              type="button"
              disabled={reportAction.loading}
              onClick={() => (item.enabled ? onGenerateReport(item.format) : onNavigate("/reports"))}
            >
              <span>{item.label}</span>
              <strong>
                {reportAction.loading && reportAction.format === item.format ? `Generating ${item.label}...` : item.enabled ? "Download" : "View Reports"}
              </strong>
              <small>{item.description}</small>
            </button>
          ))}
        </div>
        {reportAction.error ? <div className="error-box">{reportAction.error}</div> : null}
        {reportAction.success ? <div className="success-box">{reportAction.success}</div> : null}
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Archive</p>
            <h3>Generated report history</h3>
          </div>
          <span>{reportArchive.length} saved exports</span>
        </div>
        {!reportArchive.length ? (
          <div className="empty-state">No saved exports yet.</div>
        ) : (
          <div className="report-archive-list">
            {reportArchive.map((item) => (
              <article key={item.id} className="archive-card">
                <span className="table-chip">{item.format}</span>
                <strong>{item.report_type}</strong>
                <span className="muted-copy">Created {formatDate(item.created_at)}</span>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function ScheduledScansPage({ jobsState, historyState, onNavigate, onRefresh }) {
  const jobs = jobsState.jobs || [];
  const latestRecords = historyState.records.slice(0, 6);
  const runningJobs = jobs.filter((job) => ["queued", "running", "pending"].includes(String(job.status || "").toLowerCase()));

  return (
    <div className="page-grid">
      <section className="hero-panel two-column-span">
        <div className="hero-copy-block">
          <p className="eyebrow">Scheduled Scans</p>
          <h3>Queued scan activity</h3>
          <p className="hero-copy">Scheduled and async scan jobs have their own page.</p>
        </div>
        <ScoreRing score={jobs.length} label="Jobs" />
      </section>

      <section className="cards two-column-span">
        <SummaryCard label="Queued Jobs" value={jobs.length} tone="info" compact icon="◴" />
        <SummaryCard label="Active" value={runningJobs.length} tone="medium" compact icon="ϟ" />
        <SummaryCard label="Completed Scans" value={historyState.records.length} tone="low" compact icon="✓" />
        <SummaryCard label="Latest Target" value={historyState.records[0]?.target || "--"} tone="high" compact icon="▣" />
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Queue</p>
            <h3>Scheduled scan jobs</h3>
          </div>
          <button className="text-button" type="button" onClick={onRefresh}>
            Refresh
          </button>
        </div>
        {jobsState.error ? <div className="error-box">{jobsState.error}</div> : null}
        {jobsState.loading ? (
          <div className="empty-state">Loading scheduled scans...</div>
        ) : !jobs.length ? (
          <div className="empty-state">No scheduled scans yet.</div>
        ) : (
          <div className="report-archive-list">
            {jobs.map((job) => (
              <article key={job.id} className="archive-card scheduled-job-card">
                <span className="table-chip">{job.status}</span>
                <strong>{job.target}</strong>
                <span className="muted-copy">Progress {job.progress ?? 0}%</span>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel two-column-span">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Recent Results</p>
            <h3>Completed scan history</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onNavigate("/history")}>
            Open history
          </button>
        </div>
        <RecentScanList records={latestRecords} onNavigate={onNavigate} />
      </section>
    </div>
  );
}

function AdminPage({
  authState,
  adminState,
  adminUserForm,
  historyState,
  jobsState,
  onFormChange,
  onCreateUser,
  onUpdateUser,
  onDeleteUser,
  onRefresh,
  onNavigate
}) {
  if (authState.user?.role !== "admin") {
    return (
      <section className="panel page-section">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Admin</p>
            <h3>Admin access required</h3>
            <p className="muted-copy">Login with an admin account to manage users and review organization activity.</p>
          </div>
        </div>
      </section>
    );
  }

  const activeUsers = adminState.users.filter((user) => user.is_active).length;
  const adminUsers = adminState.users.filter((user) => user.role === "admin").length;

  return (
    <div className="admin-layout">
      <section className="dashboard-stats">
        <SummaryCard label="Total Users" value={adminState.users.length} tone="info" helper={`${activeUsers} active`} compact icon="◉" />
        <SummaryCard label="Admins" value={adminUsers} tone="low" helper="Privileged accounts" compact icon="⛨" />
        <SummaryCard label="All Scans" value={historyState.records.length} tone="medium" helper="All user activity" compact icon="◎" />
        <SummaryCard label="Jobs" value={jobsState.jobs.length} tone="high" helper="Organization queue" compact icon="◴" />
      </section>

      <section className="panel admin-create-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Accounts</p>
            <h3>Add new user</h3>
            <p className="muted-copy">Create analyst or admin accounts.</p>
          </div>
        </div>
        <form className="admin-user-form" onSubmit={onCreateUser}>
          <input
            value={adminUserForm.username}
            onChange={(event) => onFormChange((current) => ({ ...current, username: event.target.value }))}
            placeholder="Username"
            autoComplete="off"
          />
          <input
            type="password"
            value={adminUserForm.password}
            onChange={(event) => onFormChange((current) => ({ ...current, password: event.target.value }))}
            placeholder="Temporary password"
            autoComplete="new-password"
          />
          <select value={adminUserForm.role} onChange={(event) => onFormChange((current) => ({ ...current, role: event.target.value }))}>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
          <input
            value={adminUserForm.full_name}
            onChange={(event) => onFormChange((current) => ({ ...current, full_name: event.target.value }))}
            placeholder="Full name"
            autoComplete="off"
          />
          <input
            type="email"
            value={adminUserForm.email}
            onChange={(event) => onFormChange((current) => ({ ...current, email: event.target.value }))}
            placeholder="Email"
            autoComplete="off"
          />
          <input
            value={adminUserForm.job_title}
            onChange={(event) => onFormChange((current) => ({ ...current, job_title: event.target.value }))}
            placeholder="Job title"
            autoComplete="off"
          />
          <button className="primary-button" type="submit" disabled={adminUserForm.loading}>
            {adminUserForm.loading ? "Creating..." : "Add User"}
          </button>
        </form>
        {adminUserForm.success ? <div className="success-box">{adminUserForm.success}</div> : null}
        {adminUserForm.error ? <div className="error-box">{adminUserForm.error}</div> : null}
      </section>

      <section className="panel admin-users-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">User Management</p>
            <h3>Accounts</h3>
          </div>
          <button className="text-button" type="button" onClick={onRefresh}>
            Refresh
          </button>
        </div>
        {adminState.error ? <div className="error-box">{adminState.error}</div> : null}
        <AdminUsersTable
          users={adminState.users}
          loading={adminState.loading}
          action={adminState.action}
          currentUserId={authState.user.id}
          onUpdateUser={onUpdateUser}
          onDeleteUser={onDeleteUser}
        />
      </section>

      <section className="panel admin-activity-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">All Activity</p>
            <h3>Recent scans from every account</h3>
          </div>
          <button className="text-button" type="button" onClick={() => onNavigate("/history")}>
            Open history
          </button>
        </div>
        <HistoryTable records={historyState.records.slice(0, 12)} loading={historyState.loading} onNavigate={onNavigate} />
      </section>
    </div>
  );
}

function AdminUsersTable({ users, loading, action, currentUserId, onUpdateUser, onDeleteUser }) {
  if (loading) {
    return <div className="empty-state">Loading users...</div>;
  }
  if (!users.length) {
    return <div className="empty-state">No users found.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => {
            const busy = action === `${user.id}`;
            const isSelf = user.id === currentUserId;
            return (
              <tr key={user.id}>
                <td className="table-target">
                  <strong>{user.full_name || user.username}</strong>
                  <span className="muted-copy">@{user.username}</span>
                </td>
                <td>{user.email || "--"}</td>
                <td>
                  <select
                    value={user.role}
                    disabled={busy}
                    onChange={(event) => onUpdateUser(user.id, { role: event.target.value })}
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
                <td>
                  <span className={`table-chip ${user.is_active ? "" : "table-chip-danger"}`}>
                    {user.is_active ? "Active" : "Inactive"}
                  </span>
                </td>
                <td>{formatDate(user.created_at)}</td>
                <td>
                  <div className="inline-actions">
                    <button
                      className="table-link"
                      type="button"
                      disabled={busy || isSelf}
                      onClick={() => onUpdateUser(user.id, { is_active: !user.is_active })}
                    >
                      {user.is_active ? "Deactivate" : "Activate"}
                    </button>
                    <button
                      className="table-link danger-link"
                      type="button"
                      disabled={busy || isSelf}
                      onClick={() => onDeleteUser(user.id)}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AiButton({ children, onClick, disabled = false, compact = false }) {
  return (
    <button
      className={`ai-sparkle-button ${compact ? "ai-sparkle-button-compact" : ""}`}
      type="button"
      onClick={onClick}
      disabled={disabled}
    >
      <span className="ai-particle-field" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
      </span>
      <span className="ai-sparkle-core">
        <span className="ai-sparkle-icon" aria-hidden="true">✦</span>
        <span className="ai-mini-spark ai-mini-spark-one" aria-hidden="true">✦</span>
        <span className="ai-mini-spark ai-mini-spark-two" aria-hidden="true">✦</span>
        <span className="ai-mini-spark ai-mini-spark-three" aria-hidden="true">✦</span>
        <span className="ai-sparkle-label">{children}</span>
      </span>
    </button>
  );
}

function SettingsPage({ authState, jobsState, onNavigate }) {
  const displayName = authState.user?.full_name || authState.user?.username || "Anonymous";
  return (
    <section className="panel page-section">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Settings</p>
          <h3>Platform defaults</h3>
          <p className="muted-copy">Current runtime defaults.</p>
        </div>
      </div>
      <div className="settings-grid">
        <MetricBlock label="API Base" value="/api" />
        <MetricBlock label="Database" value="SQLite / SQLAlchemy" />
        <MetricBlock label="Storage Table" value="secureshield_scan_records" />
        <MetricBlock label="AI Mode" value="Gemini remediation + chat" />
        <MetricBlock label="Auth User" value={displayName} />
        <MetricBlock label="Queued Jobs" value={jobsState.jobs.length} />
      </div>
      <div className="panel-block">
        <span className="panel-label">Session</span>
        <div className="inline-actions">
          {authState.user ? (
            <>
              <span className="table-chip">{authState.user.role}</span>
              <strong>{displayName}</strong>
              {authState.user.email ? <span className="muted-copy">{authState.user.email}</span> : null}
            </>
          ) : (
            <span className="muted-copy">No active session.</span>
          )}
          <button className="text-button" type="button" onClick={() => onNavigate("/auth")}>
            Open auth page
          </button>
        </div>
      </div>
      <div className="panel-block">
        <span className="panel-label">Why separate page</span>
        <p className="muted-copy">Login and registration are moved out of settings so this page stays focused on platform defaults.</p>
      </div>
      <div className="panel-block">
        <span className="panel-label">Async Jobs</span>
        {jobsState.loading ? (
          <div className="empty-state">Loading jobs...</div>
        ) : !jobsState.jobs.length ? (
          <div className="empty-state">No jobs created yet.</div>
        ) : (
          <div className="report-archive-list">
            {jobsState.jobs.slice(0, 6).map((job) => (
              <article key={job.id} className="archive-card">
                <span className="table-chip">{job.status}</span>
                <strong>{job.target}</strong>
                <span className="muted-copy">Progress {job.progress}%</span>
              </article>
            ))}
          </div>
        )}
      </div>
      <div className="panel-block">
        <span className="panel-label">Next candidates</span>
        <ul className="plain-list">
          <li>Expose environment status and scanner binary checks.</li>
          <li>Tune scan defaults and history limits.</li>
          <li>Promote PostgreSQL and Redis in deployment.</li>
        </ul>
      </div>
    </section>
  );
}

function AuthPage({
  authState,
  authForm,
  onAuthChange,
  onAuthSubmit,
  profileForm,
  onProfileChange,
  onProfileSubmit,
  passwordForm,
  onPasswordChange,
  onPasswordSubmit,
  onLogout,
  onNavigate
}) {
  const isRegister = authForm.mode === "register";
  const displayName = authState.user?.full_name || authState.user?.username || "";
  const profileInitial = (authState.user?.username || "U").slice(0, 1).toUpperCase();

  if (authState.user) {
    return (
      <section className="profile-page">
        <header className="profile-page-header">
          <button className="text-button auth-back-link" type="button" onClick={() => onNavigate("/")}>
            Back to dashboard
          </button>
          <div className="profile-hero">
            <span className="profile-avatar profile-avatar-large">{profileInitial}</span>
            <div>
              <p className="eyebrow">User Profile</p>
              <h2>{displayName}</h2>
              <p className="muted-copy">
                @{authState.user.username} · {authState.user.job_title || "Security Engineer"}
              </p>
            </div>
            <span className="table-chip">{authState.user.role}</span>
          </div>
        </header>

        <main className="profile-page-grid">
          <section className="profile-panel">
            <div className="auth-card-head compact-head">
              <p className="eyebrow">Profile</p>
              <h3>Account details</h3>
              <p className="muted-copy">Update the information shown across the dashboard.</p>
            </div>
            <form className="auth-form auth-form-page profile-form" onSubmit={onProfileSubmit}>
              <label>
                <span>Full name</span>
                <input
                  value={profileForm.full_name}
                  onChange={(event) => onProfileChange((current) => ({ ...current, full_name: event.target.value }))}
                  placeholder="Your name"
                  autoComplete="name"
                />
              </label>
              <label>
                <span>Email</span>
                <input
                  type="email"
                  value={profileForm.email}
                  onChange={(event) => onProfileChange((current) => ({ ...current, email: event.target.value }))}
                  placeholder="you@example.com"
                  autoComplete="email"
                />
              </label>
              <label>
                <span>Job title</span>
                <input
                  value={profileForm.job_title}
                  onChange={(event) => onProfileChange((current) => ({ ...current, job_title: event.target.value }))}
                  placeholder="Security Engineer"
                  autoComplete="organization-title"
                />
              </label>
              <button className="primary-button auth-submit-button" type="submit" disabled={profileForm.loading}>
                {profileForm.loading ? "Saving..." : "Save profile"}
              </button>
              {profileForm.success ? <div className="success-box">{profileForm.success}</div> : null}
              {profileForm.error ? <div className="error-box">{profileForm.error}</div> : null}
            </form>
          </section>

          <section className="profile-panel">
            <div className="auth-card-head compact-head">
              <p className="eyebrow">Password</p>
              <h3>Change password</h3>
              <p className="muted-copy">Use your current password before setting a new one.</p>
            </div>
            <form className="auth-form auth-form-page profile-form" onSubmit={onPasswordSubmit}>
              <label>
                <span>Current password</span>
                <input
                  type="password"
                  value={passwordForm.current_password}
                  onChange={(event) => onPasswordChange((current) => ({ ...current, current_password: event.target.value }))}
                  placeholder="Current password"
                  autoComplete="current-password"
                />
              </label>
              <label>
                <span>New password</span>
                <input
                  type="password"
                  value={passwordForm.new_password}
                  onChange={(event) => onPasswordChange((current) => ({ ...current, new_password: event.target.value }))}
                  placeholder="At least 8 characters"
                  autoComplete="new-password"
                />
              </label>
              <label>
                <span>Confirm password</span>
                <input
                  type="password"
                  value={passwordForm.confirm_password}
                  onChange={(event) => onPasswordChange((current) => ({ ...current, confirm_password: event.target.value }))}
                  placeholder="Repeat new password"
                  autoComplete="new-password"
                />
              </label>
              <button className="primary-button auth-submit-button" type="submit" disabled={passwordForm.loading}>
                {passwordForm.loading ? "Changing..." : "Change password"}
              </button>
              {passwordForm.success ? <div className="success-box">{passwordForm.success}</div> : null}
              {passwordForm.error ? <div className="error-box">{passwordForm.error}</div> : null}
            </form>
          </section>

          <section className="profile-panel profile-session-panel">
            <div className="auth-card-head compact-head">
              <p className="eyebrow">Session</p>
              <h3>Signed in account</h3>
            </div>
            <dl className="profile-detail-list">
              <div>
                <dt>Username</dt>
                <dd>@{authState.user.username}</dd>
              </div>
              <div>
                <dt>Email</dt>
                <dd>{authState.user.email || "Not set"}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{authState.user.role}</dd>
              </div>
            </dl>
            <div className="auth-session-actions">
              <button className="primary-button" type="button" onClick={() => onNavigate("/")}>
                Open Dashboard
              </button>
              <button className="secondary-button topbar-auth-logout" type="button" onClick={onLogout}>
                Logout
              </button>
            </div>
          </section>
        </main>
      </section>
    );
  }

  return (
    <section className="auth-page">
      <article className="auth-card">
        <div className="auth-brand-panel">
          <button className="text-button auth-back-link" type="button" onClick={() => onNavigate("/")}>
            Back to dashboard
          </button>
          <div className="auth-shield-mark">
            <span>🛡</span>
          </div>
          <div className="auth-brand-copy">
            <p className="eyebrow">SecureShield Access</p>
            <h2>Container security command center</h2>
            <p className="muted-copy">Authenticate to review scans, benchmark posture, export reports, and manage remediation workflows.</p>
          </div>
          <div className="auth-signal-grid">
            <span>Trivy</span>
            <span>CIS</span>
            <span>Secrets</span>
            <span>Runtime</span>
          </div>
        </div>

        <div className="auth-form-panel">
          <div className="auth-card-head">
            <p className="eyebrow">Auth</p>
            <h3>{isRegister ? "Create your account" : "Login to SecureShield"}</h3>
            <p className="muted-copy">{isRegister ? "Start a local workspace account for scan history and reporting." : "Continue to your SecureShield dashboard."}</p>
          </div>

          <form className="auth-form auth-form-page" onSubmit={onAuthSubmit}>
              <label>
                <span>Username</span>
                <input
                  value={authForm.username}
                  onChange={(event) => onAuthChange((current) => ({ ...current, username: event.target.value }))}
                  placeholder="analyst"
                  autoComplete="username"
                />
              </label>
              <label>
                <span>Password</span>
                <input
                  type="password"
                  value={authForm.password}
                  onChange={(event) => onAuthChange((current) => ({ ...current, password: event.target.value }))}
                  placeholder="Enter password"
                  autoComplete={isRegister ? "new-password" : "current-password"}
                />
              </label>
              <button className="primary-button auth-submit-button" type="submit" disabled={authForm.loading}>
                {authForm.loading ? "Working..." : isRegister ? "Create account" : "Login now"}
              </button>
              <div className="auth-switch-copy">
                <span>{isRegister ? "Already have an account?" : "No account yet?"}</span>
                <button
                  className="text-button"
                  type="button"
                  onClick={() =>
                    onAuthChange((current) => ({
                      ...current,
                      mode: current.mode === "register" ? "login" : "register",
                      error: ""
                    }))
                  }
                >
                  {isRegister ? "Login" : "Sign up"}
                </button>
              </div>
              {authForm.error ? <div className="error-box">{authForm.error}</div> : null}
          </form>
        </div>
      </article>
    </section>
  );
}

function HistoryTable({ records, loading, onNavigate }) {
  if (loading) {
    return <div className="empty-state">Loading scan history...</div>;
  }
  if (!records.length) {
    return <div className="empty-state">No saved scans yet. Run a scan to populate history.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Target</th>
            <th>Score</th>
            <th>Created</th>
            <th>Open</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => (
            <tr key={record.id}>
              <td>{record.id}</td>
              <td>
                <span className="table-chip">{record.scan_type}</span>
              </td>
              <td className="table-target">{record.target}</td>
              <td>{record.security_score ?? "--"}</td>
              <td>{formatDate(record.created_at)}</td>
              <td>
                <button className="table-link" type="button" onClick={() => onNavigate(`/scan/${record.id}`)}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IssueTable({ issues, onAskAI, onOpenChat, aiLoading = false, chatLoading = false }) {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(issues.length / ISSUE_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * ISSUE_PAGE_SIZE;
  const visibleIssues = useMemo(() => issues.slice(pageStart, pageStart + ISSUE_PAGE_SIZE), [issues, pageStart]);

  useEffect(() => {
    setPage(1);
  }, [issues.length]);

  if (!issues.length) {
    return <div className="empty-state">No findings available for this view.</div>;
  }

  return (
    <div className="paginated-table">
      <div className="table-pagination table-pagination-top">
        <span>
          Showing {pageStart + 1}-{Math.min(pageStart + visibleIssues.length, issues.length)} of {issues.length}
        </span>
        <div className="pagination-controls">
          <button type="button" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={currentPage === 1}>
            Previous
          </button>
          <span>
            Page {currentPage} / {totalPages}
          </span>
          <button type="button" onClick={() => setPage((value) => Math.min(totalPages, value + 1))} disabled={currentPage === totalPages}>
            Next
          </button>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Module</th>
              <th>Severity</th>
              <th>ID</th>
              <th>Title</th>
              <th>Target</th>
              <th>AI</th>
              <th>Chat</th>
            </tr>
          </thead>
          <tbody>
            {visibleIssues.map((issue, index) => (
              <tr key={`${issue.id}-${issue.module}-${pageStart + index}`}>
                <td>
                  <span className="table-chip">{issue.module || "-"}</span>
                </td>
                <td>
                  <span className={`badge badge-${String(issue.severity || "unknown").toLowerCase()}`}>
                    {issue.severity || "UNKNOWN"}
                  </span>
                </td>
                <td>{issue.id}</td>
                <td>{issue.title}</td>
                <td className="table-target">{issue.target}</td>
                <td>
                  <AiButton compact onClick={() => onAskAI(issue)} disabled={aiLoading}>
                    {aiLoading ? "Working..." : "Ask AI"}
                  </AiButton>
                </td>
                <td>
                  <AiButton compact onClick={() => onOpenChat(issue)} disabled={chatLoading}>
                    {chatLoading ? "Opening..." : "AI Chat"}
                  </AiButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 ? (
        <div className="table-pagination table-pagination-bottom">
          <button type="button" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={currentPage === 1}>
            Previous
          </button>
          <span>
            Page {currentPage} / {totalPages}
          </span>
          <button type="button" onClick={() => setPage((value) => Math.min(totalPages, value + 1))} disabled={currentPage === totalPages}>
            Next
          </button>
        </div>
      ) : null}
    </div>
  );
}

function AIChatModal({ chatModal, onClose, onInputChange, onSend }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">AI Chat</p>
            <h3>{chatModal.selectedIssue?.id || "AI Security Chat"}</h3>
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="chat-log">
          {chatModal.messages.map((message, index) => (
            <div key={`${message.role}-${index}`} className={`chat-bubble chat-${message.role}`}>
              <strong>{message.role === "assistant" ? "AI" : "You"}</strong>
              <p>{message.text}</p>
              {message.disclaimer ? <span className="chat-disclaimer">{message.disclaimer}</span> : null}
            </div>
          ))}
          {chatModal.error ? <div className="error-box">{chatModal.error}</div> : null}
        </div>

        <div className="chat-composer">
          <textarea
            value={chatModal.input}
            onChange={(event) => onInputChange(event.target.value)}
            placeholder="Ask about the fix or risk..."
          />
          <div className="chat-actions">
            <button className="text-button" type="button" onClick={onClose}>
              Finished
            </button>
            <button type="button" onClick={onSend} disabled={chatModal.loading || !chatModal.input.trim()}>
              {chatModal.loading ? "Sending..." : "Send"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function DashboardDetailsModal({
  modal,
  onClose,
  historyState,
  activityItems,
  issues,
  onNavigate,
  onAskAI,
  onOpenChat,
  aiLoading,
  chatLoading
}) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell dashboard-modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">View All</p>
            <h3>{modal.title}</h3>
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            Close
          </button>
        </div>

        {modal.type === "recent_scans" ? (
          <HistoryTable records={historyState.records} loading={historyState.loading} onNavigate={onNavigate} />
        ) : null}

        {modal.type === "activity_feed" ? (
          <div className="dashboard-modal-content">
            <ActivityFeed items={activityItems} />
          </div>
        ) : null}

        {modal.type === "top_vulnerabilities" ? (
          <div className="dashboard-modal-content">
            <IssueTable issues={issues} onAskAI={onAskAI} onOpenChat={onOpenChat} aiLoading={aiLoading} chatLoading={chatLoading} />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function FloatingAIChat({ chat, onToggle, onClose, onInputChange, onSend }) {
  const quickPrompts = [
    "Why is my risk score low?",
    "How to fix critical CVEs?",
    "Explain CIS failures"
  ];

  return (
    <div className={`floating-ai ${chat.open ? "floating-ai-open" : ""}`}>
      {chat.open ? (
        <section className="floating-ai-panel" aria-label="SecureShield AI Chat">
          <div className="floating-ai-header">
            <div>
              <p className="eyebrow">SecureShield AI</p>
              <h3>Security assistant</h3>
            </div>
            <button className="modal-close" type="button" onClick={onClose}>
              Close
            </button>
          </div>

          <div className="floating-ai-log">
            {chat.messages.map((message, index) => (
              <div key={`${message.role}-${index}`} className={`chat-bubble chat-${message.role}`}>
                <strong>{message.role === "assistant" ? "AI" : "You"}</strong>
                <p>{message.text}</p>
                {message.disclaimer ? <span className="chat-disclaimer">{message.disclaimer}</span> : null}
              </div>
            ))}
            {chat.error ? <div className="error-box">{chat.error}</div> : null}
          </div>

          <div className="floating-ai-prompts">
            {quickPrompts.map((prompt) => (
              <button key={prompt} className="quick-chip" type="button" onClick={() => onSend(prompt)} disabled={chat.loading}>
                {prompt}
              </button>
            ))}
          </div>

          <div className="floating-ai-composer">
            <textarea
              value={chat.input}
              onChange={(event) => onInputChange(event.target.value)}
              placeholder="Ask how to fix a CVE, explain CIS failure, or review risk..."
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  onSend();
                }
              }}
            />
            <AiButton compact onClick={() => onSend()} disabled={chat.loading || !chat.input.trim()}>
              {chat.loading ? "Thinking..." : "Send"}
            </AiButton>
          </div>
        </section>
      ) : null}

      <button className="floating-ai-button" type="button" onClick={onToggle} aria-label="Open AI chat">
        <span>✦</span>
        <strong>AI</strong>
      </button>
    </div>
  );
}

function NotificationsPanel({ latestRecord, reportsState, jobsState, onNavigate }) {
  const latestExport = reportsState.archive?.[0];
  const latestJob = jobsState.jobs?.[0];
  const items = [
    latestRecord
      ? {
          title: "Latest scan saved",
          detail: `${latestRecord.target || "Scan"} · ${formatDate(latestRecord.created_at)}`,
          action: () => onNavigate(`/scan/${latestRecord.id}`)
        }
      : {
          title: "No scans yet",
          detail: "Run a scan to start history notifications.",
          action: () => onNavigate("/history")
        },
    latestExport
      ? {
          title: "Report export ready",
          detail: `${latestExport.format} · ${formatDate(latestExport.created_at)}`,
          action: () => onNavigate("/export")
        }
      : {
          title: "No exports yet",
          detail: "Open Export Center to generate reports.",
          action: () => onNavigate("/export")
        },
    latestJob
      ? {
          title: "Scheduled scan update",
          detail: `${latestJob.status} · ${latestJob.target}`,
          action: () => onNavigate("/scheduled")
        }
      : {
          title: "Schedule queue empty",
          detail: "Scheduled scans will appear here.",
          action: () => onNavigate("/scheduled")
        }
  ];

  return (
    <section className="notification-panel" aria-label="Notifications">
      <div className="notification-head">
        <strong>Notifications</strong>
        <span>{items.length}</span>
      </div>
      <div className="notification-list">
        {items.map((item) => (
          <button key={item.title} type="button" className="notification-item" onClick={item.action}>
            <span className="notification-dot" />
            <div>
              <strong>{item.title}</strong>
              <small>{item.detail}</small>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

function AIRemediationModal({ aiState, onClose }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-shell" onClick={(event) => event.stopPropagation()}>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">AI Remediation</p>
            <h3>{aiState.selectedIssue?.id || "Security Guidance"}</h3>
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="dashboard-modal-content">
          <AISupportPanel aiState={aiState} />
        </div>
      </div>
    </div>
  );
}

function AISupportPanel({ aiState }) {
  if (aiState.loading) {
    return <div className="empty-state">Generating remediation guidance...</div>;
  }

  if (aiState.error) {
    return <div className="error-box">{aiState.error}</div>;
  }

  if (!aiState.response) {
    return (
      <div className="empty-state">
        Pick a finding and press <strong>Ask AI</strong>.
      </div>
    );
  }

  return (
    <div className="ai-panel">
      <div className="report-grid">
        <MetricBlock label="Summary" value={aiState.response.summary || "--"} />
        <MetricBlock label="Risk" value={aiState.response.risk || "--"} />
        <MetricBlock label="Priority" value={aiState.response.priority || "--"} />
        <MetricBlock label="Safe Example" value={aiState.response.safe_example || "--"} />
      </div>
      <div className="panel-block">
        <span className="panel-label">Remediation Steps</span>
        <ul className="plain-list">
          {(aiState.response.remediation_steps || []).map((step, index) => (
            <li key={`${step}-${index}`}>{step}</li>
          ))}
        </ul>
      </div>
      <p className="muted-copy">{aiState.response.disclaimer}</p>
    </div>
  );
}

function SummaryCard({ label, value, tone, helper, compact = false, icon, spark = false }) {
  return (
    <article className={`summary-card summary-${tone} ${compact ? "summary-card-compact" : ""}`}>
      {icon ? <span className="summary-icon">{icon}</span> : null}
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{helper || summaryMessage(label, value)}</small>
      {spark ? <span className={`summary-spark summary-spark-${tone}`} /> : null}
    </article>
  );
}

function MetricMarquee({ cards }) {
  const marqueeCards = [...cards, ...cards];

  return (
    <section className="dashboard-stats metric-marquee-section" aria-label="Dashboard metric highlights">
      <div className="metric-marquee-row">
        <div className="metric-marquee-track">
          {marqueeCards.map((item, index) => (
            <SummaryCard
              key={`${item.label}-${index}`}
              label={item.label}
              value={item.value}
              tone={item.tone}
              helper={item.change}
              compact
              icon={item.icon}
              spark
            />
          ))}
        </div>
      </div>
    </section>
  );
}

function MiniStat({ label, value }) {
  return (
    <div className="mini-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function MetricBlock({ label, value }) {
  return (
    <div className="metric-block">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ScanProgressPanel({ progress }) {
  const percent = Math.max(0, Math.min(progress.percent || 0, 100));

  return (
    <section className={`scan-progress-panel ${progress.error ? "scan-progress-error" : ""}`}>
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">Live Scan Progress</p>
          <h3>{progress.phase || "Waiting to start"}</h3>
        </div>
        <span>{percent}%</span>
      </div>
      <div className="progress-track">
        <div className="progress-bar" style={{ width: `${percent}%` }} />
      </div>
      <div className="progress-meta">
        <span>{progress.module ? `Module: ${progress.module}` : "Preparing modules..."}</span>
        <span>{progress.completed ? "Saved to history" : progress.active ? "Running" : progress.error ? "Stopped" : "Idle"}</span>
      </div>
      {!!progress.events.length ? (
        <div className="progress-events">
          {progress.events.map((item, index) => (
            <span key={`${item}-${index}`} className="table-chip">
              {item}
            </span>
          ))}
        </div>
      ) : null}
      {progress.error ? <div className="error-box">{progress.error}</div> : null}
    </section>
  );
}

function StatusTile({ label, value }) {
  return (
    <article className="status-tile">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function OverviewPill({ label, value, tone }) {
  return (
    <div className={`overview-pill overview-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ScoreRing({ score, label = "Security Score" }) {
  const numeric = typeof score === "number" ? Math.max(0, Math.min(score, 100)) : null;

  return (
    <div
      className="score-ring"
      style={{
        background: numeric === null
          ? undefined
          : `radial-gradient(circle at center, rgba(7, 12, 24, 0.96) 54%, transparent 55%), conic-gradient(#ff7a18 0%, #ffb347 ${numeric / 2}%, #73ffd2 ${numeric}%, rgba(255,255,255,0.08) ${numeric}%)`
      }}
    >
      <span>{label}</span>
      <strong>{score ?? "--"}</strong>
    </div>
  );
}

function RiskCallout({ summary }) {
  const critical = summary.critical ?? 0;
  const high = summary.high ?? 0;
  const total = summary.total ?? 0;
  const tone = critical > 0 ? "critical" : high > 0 ? "high" : total > 0 ? "medium" : "low";
  const headline =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} need immediate attention.`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s are" : " is"} driving current risk.`
        : total > 0
          ? "No top-tier issues, but backlog still needs cleanup."
          : "Current view is clean.";

  return (
    <div className={`risk-callout risk-${tone}`}>
      <span className="panel-label">Risk Outlook</span>
      <strong>{headline}</strong>
    </div>
  );
}

function SeverityChart({ items }) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <div className="severity-chart">
      {items.map((item) => (
        <div className="severity-row" key={item.key}>
          <div className="severity-meta">
            <span className={`badge badge-${item.tone}`}>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
          <div className="severity-bar-track">
            <div
              className={`severity-bar severity-bar-${item.tone}`}
              style={{ width: `${(item.value / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function ModuleCard({ card }) {
  return (
    <article className="module-card">
      <div className="module-card-head">
        <strong>{card.label}</strong>
        <span className={`badge badge-${card.tone}`}>{card.status}</span>
      </div>
      <p>{card.description}</p>
      <div className="module-card-foot">
        <span>Findings: {card.count}</span>
      </div>
    </article>
  );
}

function TrendChart({ records }) {
  if (!records.length) {
    return <div className="empty-state">Run scans to populate the trend view.</div>;
  }

  const points = records.map((record, index) => {
    const total = record.summary?.total ?? 0;
    const critical = record.summary?.critical ?? 0;
    const high = record.summary?.high ?? 0;
    return {
      key: record.id || index,
      label: record.target || `Scan ${index + 1}`,
      total,
      critical,
      high
    };
  });
  const max = Math.max(...points.map((point) => point.total || point.critical || point.high || 1), 1);

  return (
    <div className="trend-chart">
      <div className="trend-canvas">
        {points.map((point) => (
          <div key={point.key} className="trend-column">
            <div className="trend-stack">
              <span className="trend-bar trend-bar-low" style={{ height: `${Math.max((point.total / max) * 100, 8)}%` }} />
              <span className="trend-bar trend-bar-high" style={{ height: `${Math.max((point.high / max) * 100, 6)}%` }} />
              <span className="trend-bar trend-bar-critical" style={{ height: `${Math.max((point.critical / max) * 100, 4)}%` }} />
            </div>
            <small>{point.label.split(":")[0]}</small>
          </div>
        ))}
      </div>
      <div className="trend-legend">
        <span><i className="legend-swatch legend-critical" />Critical</span>
        <span><i className="legend-swatch legend-high" />High</span>
        <span><i className="legend-swatch legend-total" />Total</span>
      </div>
    </div>
  );
}

function RecentScanList({ records, onNavigate }) {
  if (!records.length) {
    return <div className="empty-state">No saved scans yet.</div>;
  }

  return (
    <div className="recent-scan-list">
      {records.map((record) => {
        const summary = record.summary || zeroSummary();
        const severity = summary.critical ? "critical" : summary.high ? "high" : summary.medium ? "medium" : "low";
        return (
          <button key={record.id} type="button" className="recent-scan-item" onClick={() => onNavigate(`/scan/${record.id}`)}>
            <div>
              <strong>{record.target || `Scan ${record.id}`}</strong>
              <small>{record.created_at ? formatDate(record.created_at) : "Saved result"}</small>
            </div>
            <span className={`badge badge-${severity}`}>{summary.total ?? 0}</span>
          </button>
        );
      })}
    </div>
  );
}

function ActivityFeed({ items }) {
  if (!items.length) {
    return <div className="empty-state">Activity will appear after the first scan completes.</div>;
  }

  return (
    <div className="activity-feed">
      {items.map((item, index) => (
        <article key={`${item.title}-${index}`} className="activity-item">
          <span className={`activity-icon activity-${item.tone}`} />
          <div>
            <strong>{item.title}</strong>
            <p>{item.detail}</p>
          </div>
          <small>{item.when}</small>
        </article>
      ))}
    </div>
  );
}

function GaugeCard({ score }) {
  const numeric = Math.max(0, Number(score || 0));
  const capped = Math.min(numeric, 10);
  const percent = Math.min(Math.max((capped / 10) * 100, 0), 100);
  const controlHealth = Math.max(0, 100 - percent);
  const reviewLoad = Math.min(100, Math.max(10, 100 - controlHealth / 2));
  const rings = [
    {
      progress: percent,
      trackClassName: "ring-track-rose",
      progressClassName: "ring-progress-rose"
    },
    {
      progress: controlHealth,
      trackClassName: "ring-track-lime",
      progressClassName: "ring-progress-lime"
    },
    {
      progress: reviewLoad,
      trackClassName: "ring-track-teal",
      progressClassName: "ring-progress-teal"
    }
  ];

  return (
    <div className="gauge-card">
      <RingChart size={96} gap={4} width={20} rings={rings}>
        <div className="gauge-center">
          <strong>{capped.toFixed(1)}</strong>
          <span>/10</span>
          <small>Risk Score</small>
        </div>
      </RingChart>
      <div className="gauge-risk-label">{riskLabel(capped)}</div>
    </div>
  );
}

function RingChart({ size = 96, gap = 4, width = 20, rings, children }) {
  const totalWidth = calculateRingSize({ size, width, gap, index: 0, total: rings.length });

  return (
    <div
      className="ring-chart"
      style={{
        width: totalWidth + gap * rings.length * 4,
        height: totalWidth + gap * rings.length * 4
      }}
    >
      {rings.map((ring, index) => {
        const ringSize = calculateRingSize({ size, width, gap, index, total: rings.length });
        return (
          <DonutRing
            key={`ring-${index}`}
            size={ringSize}
            progress={ring.progress}
            width={width}
            trackClassName={ring.trackClassName}
            progressClassName={ring.progressClassName}
          />
        );
      })}
      <div className="ring-chart-center">{children}</div>
    </div>
  );
}

function DonutRing({ size, progress, width, trackClassName, progressClassName }) {
  const radius = (size - width) / 2;
  const circumference = 2 * Math.PI * radius;
  const normalizedProgress = Math.min(100, Math.max(0, Number(progress || 0)));
  const offset = circumference - (normalizedProgress / 100) * circumference;

  return (
    <svg className="donut-ring" width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
      <circle
        className={`donut-ring-track ${trackClassName}`}
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        strokeWidth={width}
      />
      <circle
        className={`donut-ring-progress ${progressClassName}`}
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        strokeWidth={width}
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
      />
    </svg>
  );
}

function calculateRingSize({ size = 96, width = 20, gap = 4, index, total }) {
  const position = total - index;
  return size + position * width * 2 + gap * position * 2;
}

function riskLabel(score) {
  if (score >= 7) {
    return "High Risk";
  }
  if (score >= 4) {
    return "Moderate Risk";
  }
  return "Low Risk";
}

function TopVulnerabilitiesList({ issues, onOpenLatestIssue }) {
  if (!issues.length) {
    return <div className="empty-state">No vulnerabilities available yet.</div>;
  }

  return (
    <div className="top-vuln-list">
      {issues.map((issue, index) => (
        <button key={`${issue.id || issue.title}-${index}`} type="button" className="top-vuln-item" onClick={onOpenLatestIssue}>
          <span className={`top-vuln-icon top-vuln-${normalizeTone(issue.severity)}`}>✦</span>
          <div>
            <strong>{issue.id || "Unknown issue"}</strong>
            <p>{issue.title || issue.target || "Latest normalized finding"}</p>
          </div>
          <span className={`badge badge-${normalizeTone(issue.severity)}`}>{issue.severity || "LOW"}</span>
        </button>
      ))}
    </div>
  );
}

function CisBenchmarkCard({ summary, score, onNavigate }) {
  const total = Math.max(summary.passed + summary.failed + summary.warning + summary.notRun, 1);
  const degrees = Math.max(0, Math.min(Number(score || 0), 100));
  const items = [
    { label: "Passed", value: summary.passed, tone: "low" },
    { label: "Failed", value: summary.failed, tone: "critical" },
    { label: "Warning", value: summary.warning, tone: "medium" },
    { label: "Not Run", value: summary.notRun, tone: "info" }
  ];

  return (
    <div className="cis-card">
      <DonutChart
        size={200}
        progress={degrees}
        circleWidth={16}
        progressWidth={16}
        rounded
        className="cis-donut"
        trackClassName="donut-track-muted"
        progressClassName="donut-progress-cis"
      >
        <div className="cis-progress-center">
          <strong>{degrees}%</strong>
          <span>Overall Score</span>
        </div>
      </DonutChart>
      <div className="cis-breakdown">
        {items.map((item) => (
          <div key={item.label} className="cis-breakdown-item">
            <span className={`risk-swatch risk-swatch-${item.tone}`} />
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
      <div className="cis-footer">
        <small>{total} total checks analyzed</small>
        <button className="primary-button" type="button" onClick={() => onNavigate("/reports")}>
          View CIS Benchmark
        </button>
      </div>
    </div>
  );
}

function DonutChart({
  size,
  progress,
  trackClassName = "donut-track-muted",
  progressClassName = "donut-progress-cis",
  circleWidth = 16,
  progressWidth = 16,
  rounded = true,
  className = "",
  children
}) {
  const [shouldUseValue, setShouldUseValue] = useState(false);
  const radius = size / 2 - Math.max(progressWidth, circleWidth) / 2;
  const circumference = Math.PI * radius * 2;
  const normalizedProgress = Math.min(100, Math.max(0, Number(progress || 0)));
  const percentage = shouldUseValue ? circumference * ((100 - normalizedProgress) / 100) : circumference;

  useEffect(() => {
    const timeout = window.setTimeout(() => setShouldUseValue(true), 250);
    return () => window.clearTimeout(timeout);
  }, [normalizedProgress]);

  return (
    <div className={className}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <circle
          r={radius}
          cx={size / 2}
          cy={size / 2}
          fill="transparent"
          strokeWidth={circleWidth}
          strokeDasharray="10px 0"
          strokeDashoffset="0px"
          className={`donut-chart-track ${trackClassName}`}
        />
        <circle
          r={radius}
          cx={size / 2}
          cy={size / 2}
          className={`donut-chart-progress ${progressClassName}`}
          strokeWidth={progressWidth}
          strokeLinecap={rounded ? "round" : "butt"}
          fill="transparent"
          strokeDasharray={`${circumference}px`}
          strokeDashoffset={`${percentage}px`}
        />
      </svg>
      {children}
    </div>
  );
}

function SecurityPostureCard({ metrics }) {
  const cards = metrics.map((metric) => ({
    color: "#120F17",
    title: metric.label,
    label: `${metric.value}/10`,
    count: metric.value,
    description: postureDescription(metric.label, metric.value)
  }));

  return (
    <MagicBento
      cards={cards}
      textAutoHide
      enableStars
      enableSpotlight
      enableBorderGlow
      enableTilt
      enableMagnetism
      clickEffect
      spotlightRadius={260}
      particleCount={10}
      glowColor="132, 0, 255"
    />
  );
}

function postureDescription(label, value) {
  const score = Number(value || 0);
  const status = score >= 8 ? "strong" : score >= 5 ? "needs monitoring" : "needs attention";
  return `${label} posture is ${status} based on the latest scan evidence.`;
}

function ExportReportsCard({ onNavigate, onGenerateReport }) {
  const items = ["PDF", "JSON", "CSV", "SARIF"];

  return (
    <div className="export-card">
      <div className="export-icons">
        {items.map((item) => (
          <button
            key={item}
            type="button"
            className="export-icon-box"
            onClick={() => {
              if (item === "JSON") {
                onGenerateReport("json");
                return;
              }
              if (item === "CSV") {
                onGenerateReport("csv");
                return;
              }
              onNavigate("/reports");
            }}
          >
            <span>{item}</span>
          </button>
        ))}
      </div>
      <button className="primary-button export-button" type="button" onClick={() => onNavigate("/reports")}>
        View All Reports
      </button>
    </div>
  );
}

function buildModuleCards(scanResult) {
  const issues = scanResult?.issues || [];
  const runtimeChecks = scanResult?.modules?.runtime?.checks || [];
  const cisChecks = scanResult?.modules?.cis?.checks || [];
  const supplyChecks = scanResult?.modules?.supply_chain?.checks || [];
  const secretFindings = scanResult?.modules?.secrets?.findings || [];

  return [
    {
      key: "cis",
      label: "CIS Benchmark",
      count: cisChecks.filter((item) => item.status === "fail").length,
      status: cisChecks.some((item) => item.status === "fail") ? "Needs Review" : "Clean",
      tone: cisChecks.some((item) => item.status === "fail") ? "medium" : "low",
      description: "Root user, health checks, privilege controls, seccomp, and image hygiene signals."
    },
    {
      key: "secrets",
      label: "Secrets Detection",
      count: secretFindings.length,
      status: secretFindings.length ? "Secrets Found" : "No Secrets",
      tone: secretFindings.length ? "high" : "low",
      description: "Searches for keys, tokens, credentials, and suspicious high-entropy material."
    },
    {
      key: "supply_chain",
      label: "Supply Chain Risk",
      count: supplyChecks.filter((item) => item.status === "fail").length,
      status: supplyChecks.some((item) => item.status === "fail") ? "Risk Present" : "Clean",
      tone: supplyChecks.some((item) => item.status === "fail") ? "medium" : "low",
      description: "Mutable tags, provenance gaps, and suspicious startup command patterns."
    },
    {
      key: "runtime",
      label: "Runtime Security",
      count: runtimeChecks.filter((item) => item.status === "fail").length,
      status: runtimeChecks.some((item) => item.status === "fail") ? "Unsafe Runtime" : "Stable",
      tone: runtimeChecks.some((item) => item.status === "fail") ? "high" : "low",
      description: "Privileged mode, host namespaces, host networking, and dangerous mounts."
    },
    {
      key: "vuln",
      label: "Vulnerabilities",
      count: issues.filter((item) => item.module === "cve").length,
      status: issues.some((item) => item.module === "cve" && item.severity === "CRITICAL") ? "Critical CVEs" : "Tracked",
      tone: issues.some((item) => item.module === "cve" && item.severity === "CRITICAL") ? "critical" : "high",
      description: "Image CVEs normalized from Trivy into one result stream for review and reporting."
    }
  ];
}

function buildCisSummary(scanResult) {
  const checks = scanResult?.modules?.cis?.checks || [];
  return {
    passed: checks.filter((item) => item.status === "pass").length,
    failed: checks.filter((item) => item.status === "fail").length,
    warning: checks.filter((item) => item.status === "warn").length,
    notRun: checks.filter((item) => !item.status || item.status === "skip").length
  };
}

function calculateCisScore(scanResult) {
  const summary = buildCisSummary(scanResult);
  const total = summary.passed + summary.failed + summary.warning + summary.notRun;
  return total ? Math.round((summary.passed / total) * 100) : 0;
}

function isAnalyzeRoute(routeName) {
  return ["vulnerabilities", "cis", "secrets", "supply_chain", "runtime"].includes(routeName);
}

function analyzeNavItems() {
  return [
    { key: "vulnerabilities", label: "Vulnerabilities", path: "/vulnerabilities", icon: "⛨" },
    { key: "cis", label: "CIS Benchmark", path: "/cis", icon: "✓" },
    { key: "secrets", label: "Secrets Detection", path: "/secrets", icon: "⌘" },
    { key: "supply_chain", label: "Supply Chain", path: "/supply-chain", icon: "◇" },
    { key: "runtime", label: "Runtime Security", path: "/runtime", icon: "✦" }
  ];
}

function analyzeDisplayValue(routeName, { scanResult, moduleCard, moduleIssues, moduleChecks }) {
  if (routeName === "cis") {
    return calculateCisScore(scanResult);
  }
  if (routeName === "vulnerabilities" || routeName === "secrets") {
    return moduleCard?.count ?? moduleIssues.length;
  }
  return analyzeHealthScore(routeName, { scanResult, moduleCard, moduleIssues, moduleChecks });
}

function analyzeHealthScore(routeName, { scanResult, moduleCard, moduleIssues, moduleChecks }) {
  if (routeName === "cis") {
    return calculateCisScore(scanResult);
  }
  if (routeName === "vulnerabilities" || routeName === "secrets") {
    return Math.max(0, Math.min(100, 100 - (moduleCard?.count ?? moduleIssues.length) * 12));
  }
  const total = moduleChecks.length;
  if (!total) {
    return 0;
  }
  const failing = moduleChecks.filter((row) => statusTone(row.status) === "critical").length;
  return Math.round(((total - failing) / total) * 100);
}

function analyzeConfig(routeName) {
  return ANALYZE_CONFIGS[routeName] || ANALYZE_CONFIGS.vulnerabilities;
}

function extractModuleRows(scanResult, moduleKey) {
  const modulePayload = scanResult?.modules?.[moduleKey] || {};
  const rows = [
    ...(modulePayload.checks || []),
    ...(modulePayload.findings || []),
    ...(modulePayload.issues || []),
    ...(modulePayload.results || [])
  ];
  return rows.map((row) => ({
    ...row,
    status: row.status || row.severity || row.result || "info",
    title: row.title || row.name || row.check || row.rule || row.id,
    evidence: row.evidence || row.message || row.description || row.remediation || row.reason
  }));
}

function buildActivityFeed({ latestRecord, latestIssues, moduleCards, summary }) {
  const items = [];

  if (latestRecord) {
    items.push({
      title: "Scan completed",
      detail: latestRecord.target || "Latest target processed",
      when: latestRecord.created_at ? formatRelativeTime(latestRecord.created_at) : "recently",
      tone: "low"
    });
  }

  if ((summary.critical ?? 0) > 0) {
    items.push({
      title: "Critical vulnerability found",
      detail: `${summary.critical} critical issue${summary.critical > 1 ? "s" : ""} require immediate review.`,
      when: "active",
      tone: "critical"
    });
  }

  const moduleSignal = moduleCards.find((card) => card.count > 0);
  if (moduleSignal) {
    items.push({
      title: `${moduleSignal.label} updated`,
      detail: `${moduleSignal.count} finding${moduleSignal.count > 1 ? "s" : ""} in the latest pass.`,
      when: "live",
      tone: moduleSignal.tone
    });
  }

  const topIssue = latestIssues[0];
  if (topIssue) {
    items.push({
      title: topIssue.id || "New finding",
      detail: topIssue.title || topIssue.target || "Review the latest normalized issue.",
      when: (topIssue.severity || "tracked").toLowerCase(),
      tone: normalizeTone(topIssue.severity)
    });
  }

  return items.slice(0, 5);
}

function buildPostureMetrics({ scanResult, summary }) {
  const cisChecks = scanResult?.modules?.cis?.checks || [];
  const runtimeChecks = scanResult?.modules?.runtime?.checks || [];
  const supplyChecks = scanResult?.modules?.supply_chain?.checks || [];
  const secretFindings = scanResult?.modules?.secrets?.findings || [];

  return [
    { label: "Vulnerabilities", value: clampTen(10 - (summary.critical ?? 0) - (summary.high ?? 0) / 3) },
    { label: "CIS Benchmark", value: clampTen((cisChecks.filter((item) => item.status === "pass").length / Math.max(cisChecks.length, 1)) * 10) },
    { label: "Secrets Detection", value: clampTen(10 - secretFindings.length) },
    { label: "Supply Chain", value: clampTen((supplyChecks.filter((item) => item.status !== "fail").length / Math.max(supplyChecks.length, 1)) * 10) },
    { label: "Runtime Security", value: clampTen((runtimeChecks.filter((item) => item.status !== "fail").length / Math.max(runtimeChecks.length, 1)) * 10) },
    { label: "Compliance", value: clampTen(7 + ((summary.low ?? 0) > 0 ? 0.3 : 0)) }
  ];
}

function viewTitle(route) {
  if (route.name === "history") {
    return "Review stored scan evidence and reopen records";
  }
  if (route.name === "reports") {
    return "Understand aggregate exposure across saved scans";
  }
  if (isAnalyzeRoute(route.name)) {
    return analyzeConfig(route.name).description;
  }
  if (route.name === "export") {
    return "Generate and archive report exports";
  }
  if (route.name === "scheduled") {
    return "Review queued and scheduled scan activity";
  }
  if (route.name === "admin") {
    return "Manage users and review organization activity";
  }
  if (route.name === "settings") {
    return "Inspect the current platform defaults";
  }
  if (route.name === "auth") {
    return "Login or create a local account";
  }
  if (route.name === "detail") {
    return "Inspect one scan deeply and drive remediation";
  }
  return "Scan images, measure risk, and prioritize fixes";
}

function viewDescription(route) {
  if (route.name === "history") {
    return "Review saved scans.";
  }
  if (route.name === "reports") {
    return "Review and export report data.";
  }
  if (isAnalyzeRoute(route.name)) {
    return analyzeConfig(route.name).tableTitle;
  }
  if (route.name === "export") {
    return "Download reports and inspect export history.";
  }
  if (route.name === "scheduled") {
    return "Track queued scan jobs.";
  }
  if (route.name === "admin") {
    return "Admin controls for accounts and all scan activity.";
  }
  if (route.name === "settings") {
    return "Runtime defaults and setup.";
  }
  if (route.name === "auth") {
    return "Separate login and registration page.";
  }
  if (route.name === "detail") {
    return "Filter and inspect findings.";
  }
  return "Run a scan and review the result.";
}

function resolveIssueImage(issue, record, latestRecord, latestRecordDetail, dashboardResult) {
  return (
    record?.target ||
    record?.result?.image ||
    latestRecord?.target ||
    latestRecordDetail?.target ||
    dashboardResult?.image ||
    issue?.target ||
    null
  );
}

function zeroSummary() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0 };
}

function readRoute() {
  const path = window.location.pathname;
  if (path === "/history") {
    return { name: "history" };
  }
  if (path === "/reports") {
    return { name: "reports" };
  }
  if (path === "/vulnerabilities") {
    return { name: "vulnerabilities" };
  }
  if (path === "/cis") {
    return { name: "cis" };
  }
  if (path === "/secrets") {
    return { name: "secrets" };
  }
  if (path === "/supply-chain") {
    return { name: "supply_chain" };
  }
  if (path === "/runtime") {
    return { name: "runtime" };
  }
  if (path === "/export") {
    return { name: "export" };
  }
  if (path === "/scheduled") {
    return { name: "scheduled" };
  }
  if (path === "/admin") {
    return { name: "admin" };
  }
  if (path === "/settings") {
    return { name: "settings" };
  }
  if (path === "/auth") {
    return { name: "auth" };
  }
  if (path.startsWith("/scan/")) {
    return { name: "detail", id: path.split("/")[2] };
  }
  return { name: "dashboard" };
}

function queueHashScroll(hash) {
  const targetHash = hash.startsWith("#") ? hash : `#${hash}`;
  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      const target = document.querySelector(targetHash);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });
}

function formatDate(value) {
  if (!value) {
    return "--";
  }
  return new Date(value).toLocaleString();
}

function formatRelativeTime(value) {
  if (!value) {
    return "recently";
  }

  const delta = Date.now() - new Date(value).getTime();
  const minutes = Math.max(Math.round(delta / 60000), 0);
  if (minutes < 1) {
    return "just now";
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

function normalizeTone(value) {
  const tone = String(value || "").toLowerCase();
  if (tone === "critical") {
    return "critical";
  }
  if (tone === "high") {
    return "high";
  }
  if (tone === "medium") {
    return "medium";
  }
  return "low";
}

function statusTone(value) {
  const tone = String(value || "").toLowerCase();
  if (["fail", "failed", "critical", "error", "unsafe"].includes(tone)) {
    return "critical";
  }
  if (["warn", "warning", "high", "medium", "risk"].includes(tone)) {
    return "medium";
  }
  if (["pass", "passed", "ok", "clean", "success"].includes(tone)) {
    return "low";
  }
  return "info";
}

function severityRank(value) {
  const tone = String(value || "").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].indexOf(tone);
}

function clampTen(value) {
  return Number(Math.max(0, Math.min(10, value || 0)).toFixed(1));
}

function navGlyph(icon) {
  const glyphs = {
    home: "⌂",
    zap: "ϟ",
    image: "▣",
    monitor: "⌁",
    server: "◫",
    cluster: "◌",
    shield: "⛨",
    check: "✓",
    key: "⌘",
    diamond: "◇",
    spark: "✦",
    history: "◷",
    report: "☰",
    export: "⇪",
    clock: "◴",
    users: "◉",
    plug: "⊕",
    settings: "⚙"
  };
  return glyphs[icon] || "•";
}

function summaryMessage(label, value) {
  const numeric = typeof value === "number" ? value : Number(value);
  if (Number.isNaN(numeric)) {
    return "Latest snapshot";
  }
  if (label === "Critical") {
    return numeric > 0 ? "Escalate now" : "No blocker";
  }
  if (label === "High") {
    return numeric > 0 ? "Prioritize soon" : "Stable";
  }
  if (label === "Medium") {
    return numeric > 0 ? "Track and schedule" : "Quiet";
  }
  if (label === "Low") {
    return numeric > 0 ? "Hygiene backlog" : "Clear";
  }
  return "Latest snapshot";
}

function runScanWithProgress(image, sourcePath, setScanProgress, apiFetch, authToken) {
  return new Promise((resolve, reject) => {
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const tokenQuery = authToken ? `?token=${encodeURIComponent(authToken)}` : "";
    const socket = new window.WebSocket(`${protocol}://${window.location.host}/ws/scan${tokenQuery}`);
    let settled = false;
    let fallbackStarted = false;

    async function runHttpFallback() {
      if (fallbackStarted || settled) {
        return;
      }
      fallbackStarted = true;
      setScanProgress((current) => ({
        ...current,
        active: true,
        phase: "Running scan without live updates...",
        percent: Math.max(current.percent, 20),
        events: ["HTTP scan fallback active", ...current.events].slice(0, 8),
        error: ""
      }));

      try {
        const query = sourcePath.trim() ? `?source_path=${encodeURIComponent(sourcePath.trim())}` : "";
        const response = await apiFetch(`/api/scan/${encodeURIComponent(image)}${query}`);
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.detail || "Scan failed");
        }
        if (settled) {
          return;
        }
        settled = true;
        setScanProgress((current) => ({
          ...current,
          active: false,
          completed: true,
          phase: data.duplicate ? "Loaded saved scan" : "Scan completed",
          percent: 100,
          events: [data.duplicate ? "Saved result loaded" : "HTTP scan completed", ...current.events].slice(0, 8),
          error: ""
        }));
        resolve(data);
      } catch (error) {
        if (settled) {
          return;
        }
        settled = true;
        reject(error instanceof Error ? error : new Error("Scan failed"));
      }
    }

    function finishError(message) {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Error(message));
      try {
        socket.close();
      } catch {
        // Ignore close errors from already-closing sockets.
      }
    }

    socket.addEventListener("open", () => {
      setScanProgress((current) => ({
        ...current,
        phase: "Submitting scan job...",
        percent: Math.max(current.percent, 15),
        events: ["Scan request submitted", ...current.events].slice(0, 8)
      }));
      socket.send(JSON.stringify({ image, source_path: sourcePath.trim() || null }));
    });

    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.event === "progress") {
        const nextPercent = progressPercentFromEvent(message);
        const nextLabel = progressLabelFromEvent(message);
        setScanProgress((current) => ({
          ...current,
          active: true,
          phase: nextLabel,
          module: message.module || current.module,
          percent: Math.max(current.percent, nextPercent),
          events: [nextLabel, ...current.events.filter((item) => item !== nextLabel)].slice(0, 8),
          error: ""
        }));
        return;
      }

      if (message.event === "result") {
        if (settled) {
          return;
        }
        settled = true;
        resolve(message.data);
        socket.close();
        return;
      }

      if (message.event === "error") {
        finishError(message.detail || "Scan failed");
      }
    });

    socket.addEventListener("error", () => {
      void runHttpFallback();
    });

    socket.addEventListener("close", () => {
      if (!settled && !fallbackStarted) {
        void runHttpFallback();
      }
    });
  });
}

function readStoredAuth() {
  try {
    const raw = window.localStorage.getItem("secureshield-auth");
    if (!raw) {
      return { token: "", user: null };
    }
    const parsed = JSON.parse(raw);
    return { token: parsed.token || "", user: parsed.user || null };
  } catch {
    return { token: "", user: null };
  }
}

function storeAuth(value) {
  window.localStorage.setItem("secureshield-auth", JSON.stringify(value));
}

function progressPercentFromEvent(event) {
  if (event.phase === "scan_started") {
    return 12;
  }
  if (event.phase === "module_started") {
    return {
      cve: 28,
      cis: 46,
      supply_chain: 62,
      runtime: 78,
      secrets: 86
    }[event.module] || 20;
  }
  if (event.phase === "module_completed") {
    return {
      cve: 40,
      cis: 58,
      supply_chain: 74,
      runtime: 90,
      secrets: 94
    }[event.module] || 70;
  }
  if (event.phase === "scan_completed") {
    return 100;
  }
  return 20;
}

function progressLabelFromEvent(event) {
  if (event.phase === "scan_started") {
    return `Starting scan for ${event.image}`;
  }
  if (event.phase === "module_started") {
    return `Running ${formatModuleName(event.module)} checks`;
  }
  if (event.phase === "module_completed") {
    return `${formatModuleName(event.module)} completed with ${event.findings ?? 0} findings`;
  }
  if (event.phase === "scan_completed") {
    return `Completed with score ${event.security_score ?? "--"}`;
  }
  return "Processing scan update";
}

function formatModuleName(value) {
  return String(value || "scan").replaceAll("_", " ");
}
