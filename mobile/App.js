import React, { useState, useEffect, useCallback } from "react";
import {
  StyleSheet, Text, View, TouchableOpacity, ActivityIndicator,
  ScrollView, Modal, TextInput, Linking, Alert, Platform,
} from "react-native";
import { StatusBar } from "expo-status-bar";
import { CameraView, useCameraPermissions } from "expo-camera";
import AsyncStorage from "@react-native-async-storage/async-storage";

// ---- Theme (matches the web dashboard) --------------------------------
const C = {
  bg: "#0a0e17", card: "#121826", border: "#232f4a", input: "#1a233a",
  text: "#f8fafc", sub: "#94a3b8", muted: "#64748b",
  safe: "#10b981", caution: "#f59e0b", danger: "#ef4444", accent: "#06b6d4",
};

const VERDICT = {
  safe: { color: C.safe, label: "SAFE", emoji: "✅" },
  caution: { color: C.caution, label: "CAUTION", emoji: "⚠️" },
  dangerous: { color: C.danger, label: "DANGEROUS", emoji: "🛑" },
  error: { color: C.caution, label: "SCAN FAILED", emoji: "❓" },
};

const STORAGE_KEY = "qi_backend_url";

export default function App() {
  const [permission, requestPermission] = useCameraPermissions();
  const [backendUrl, setBackendUrl] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [draftUrl, setDraftUrl] = useState("");
  const [scanned, setScanned] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null); // {payload, classification, risk}

  // Load saved backend URL once.
  useEffect(() => {
    (async () => {
      try {
        const saved = await AsyncStorage.getItem(STORAGE_KEY);
        if (saved) setBackendUrl(saved);
        else setSettingsOpen(true); // first run: prompt for URL
      } catch (e) { /* ignore */ }
    })();
  }, []);

  const saveUrl = async () => {
    const u = draftUrl.trim().replace(/\/+$/, "");
    if (!u.startsWith("http")) {
      Alert.alert("Invalid URL", "Enter the full backend URL, e.g. https://xxx.trycloudflare.com");
      return;
    }
    setBackendUrl(u);
    try { await AsyncStorage.setItem(STORAGE_KEY, u); } catch (e) {}
    setSettingsOpen(false);
  };

  const analyze = useCallback(async (payloadText) => {
    if (!backendUrl) { setSettingsOpen(true); return; }
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`${backendUrl}/api/scan-payload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: payloadText, perform_network_checks: true }),
      });
      const data = await res.json();
      const details = data && data.details;
      if (!data || data.success === false || !details || !details.risk_assessment) {
        setResult({
          payload: payloadText, classification: data && data.classification,
          risk: { verdict: "error", score: null,
            summary: (data && data.message) || "Could not analyse this code — do not assume it is safe.",
            breakdown: [] },
        });
      } else {
        setResult({
          payload: payloadText,
          classification: data.classification,
          risk: details.risk_assessment,
        });
      }
    } catch (e) {
      setResult({
        payload: payloadText, classification: null,
        risk: { verdict: "error", score: null,
          summary: "Could not reach the backend. Check the URL in Settings and that the tunnel is running.",
          breakdown: [] },
      });
    } finally {
      setLoading(false);
    }
  }, [backendUrl]);

  const onBarcode = ({ data }) => {
    if (scanned || loading) return;
    setScanned(true);
    analyze(data);
  };

  const rescan = () => { setResult(null); setScanned(false); };

  // ---- Permission gate ------------------------------------------------
  if (!permission) {
    return <View style={styles.center}><ActivityIndicator color={C.accent} /></View>;
  }
  if (!permission.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.title}>Camera access needed</Text>
        <Text style={styles.sub}>The scanner uses your camera to read QR codes.</Text>
        <TouchableOpacity style={styles.btnPrimary} onPress={requestPermission}>
          <Text style={styles.btnPrimaryText}>Grant permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar style="light" />
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.logo}>🛡️ Quishing <Text style={{ color: C.accent }}>Inspector</Text></Text>
        <TouchableOpacity onPress={() => { setDraftUrl(backendUrl); setSettingsOpen(true); }}>
          <Text style={styles.gear}>⚙️</Text>
        </TouchableOpacity>
      </View>

      {/* Camera */}
      <View style={styles.cameraWrap}>
        {!result && (
          <CameraView
            style={StyleSheet.absoluteFill}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
            onBarcodeScanned={scanned ? undefined : onBarcode}
          />
        )}
        {!result && <View style={styles.reticle} pointerEvents="none" />}
        {!result && (
          <Text style={styles.hint}>Point the camera at a QR code</Text>
        )}
        {loading && (
          <View style={styles.loadingOverlay}>
            <ActivityIndicator size="large" color={C.accent} />
            <Text style={styles.loadingText}>Inspecting through secure backend…</Text>
          </View>
        )}
      </View>

      {/* Result */}
      {result && <ResultCard result={result} onRescan={rescan} />}

      {/* Settings modal */}
      <Modal visible={settingsOpen} transparent animationType="slide">
        <View style={styles.modalBg}>
          <View style={styles.modalCard}>
            <Text style={styles.title}>Backend URL</Text>
            <Text style={styles.sub}>
              Paste your Cloudflare tunnel URL for the Q Inspect backend.
            </Text>
            <TextInput
              style={styles.textInput}
              value={draftUrl}
              onChangeText={setDraftUrl}
              placeholder="https://xxxx.trycloudflare.com"
              placeholderTextColor={C.muted}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
            <TouchableOpacity style={styles.btnPrimary} onPress={saveUrl}>
              <Text style={styles.btnPrimaryText}>Save</Text>
            </TouchableOpacity>
            {!!backendUrl && (
              <TouchableOpacity onPress={() => setSettingsOpen(false)}>
                <Text style={styles.linkText}>Cancel</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>
      </Modal>
    </View>
  );
}

function ResultCard({ result, onRescan }) {
  const risk = result.risk || {};
  const v = VERDICT[(risk.verdict || "error").toLowerCase()] || VERDICT.error;
  const isUrl = result.classification === "url";
  const payload = result.payload || "";

  const openAnyway = () => {
    Alert.alert(
      "Open this link?",
      `You are about to open:\n\n${payload}\n\nThis was flagged ${v.label}. Continue only if you are sure.`,
      [
        { text: "Cancel", style: "cancel" },
        { text: "Open anyway", style: "destructive", onPress: () => Linking.openURL(payload).catch(() => {}) },
      ]
    );
  };

  return (
    <ScrollView style={styles.resultScroll} contentContainerStyle={styles.resultContent}>
      <View style={[styles.verdictBanner, { borderColor: v.color }]}>
        <Text style={[styles.verdictEmoji]}>{v.emoji}</Text>
        <Text style={[styles.verdictLabel, { color: v.color }]}>{v.label}</Text>
        {risk.score != null && (
          <Text style={styles.score}>{risk.score}<Text style={styles.scoreMax}>/100</Text></Text>
        )}
        <Text style={styles.summary}>{risk.summary}</Text>
      </View>

      <View style={styles.metaRow}>
        <Text style={styles.metaLabel}>TYPE</Text>
        <Text style={styles.metaValue}>{(result.classification || "unknown").toUpperCase()}</Text>
      </View>
      <View style={styles.payloadBox}>
        <Text style={styles.metaLabel}>DECODED CONTENT</Text>
        <Text style={styles.payloadText} numberOfLines={4}>{payload}</Text>
      </View>

      {Array.isArray(risk.breakdown) && risk.breakdown.length > 0 && (
        <View style={styles.indicators}>
          <Text style={styles.sectionTitle}>Threat indicators ({risk.breakdown.length})</Text>
          {risk.breakdown.map((b, i) => (
            <View key={i} style={styles.indicatorRow}>
              <Text style={styles.indicatorText}>{b.indicator}</Text>
              <Text style={[styles.indicatorPts, { color: sevColor(b.severity) }]}>+{b.points}</Text>
            </View>
          ))}
        </View>
      )}

      <TouchableOpacity style={styles.btnPrimary} onPress={onRescan}>
        <Text style={styles.btnPrimaryText}>Scan another</Text>
      </TouchableOpacity>

      {isUrl && (
        <TouchableOpacity style={[styles.btnGhost, { borderColor: v.color }]} onPress={openAnyway}>
          <Text style={[styles.btnGhostText, { color: v.color }]}>Open anyway</Text>
        </TouchableOpacity>
      )}
    </ScrollView>
  );
}

function sevColor(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") return C.danger;
  if (s === "medium") return C.caution;
  return C.sub;
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: C.bg },
  center: { flex: 1, backgroundColor: C.bg, alignItems: "center", justifyContent: "center", padding: 24 },
  header: {
    paddingTop: Platform.OS === "android" ? 44 : 56, paddingBottom: 12, paddingHorizontal: 18,
    flexDirection: "row", alignItems: "center", justifyContent: "space-between",
    backgroundColor: C.card, borderBottomWidth: 1, borderBottomColor: C.border,
  },
  logo: { color: C.text, fontSize: 18, fontWeight: "800" },
  gear: { fontSize: 22 },
  cameraWrap: { flex: 1, backgroundColor: "#000", alignItems: "center", justifyContent: "center" },
  reticle: {
    width: 220, height: 220, borderWidth: 3, borderColor: C.accent, borderRadius: 20,
    backgroundColor: "transparent",
  },
  hint: { position: "absolute", bottom: 40, color: C.text, fontSize: 15, opacity: 0.9 },
  loadingOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: "rgba(10,14,23,0.85)", alignItems: "center", justifyContent: "center" },
  loadingText: { color: C.sub, marginTop: 14, fontSize: 15 },

  title: { color: C.text, fontSize: 20, fontWeight: "700", marginBottom: 8, textAlign: "center" },
  sub: { color: C.sub, fontSize: 14, marginBottom: 16, textAlign: "center" },

  resultScroll: { flex: 1, backgroundColor: C.bg },
  resultContent: { padding: 18, paddingBottom: 40 },
  verdictBanner: { backgroundColor: C.card, borderWidth: 2, borderRadius: 18, padding: 22, alignItems: "center", marginBottom: 18 },
  verdictEmoji: { fontSize: 40 },
  verdictLabel: { fontSize: 24, fontWeight: "900", letterSpacing: 1, marginTop: 6 },
  score: { color: C.text, fontSize: 40, fontWeight: "800", marginTop: 8 },
  scoreMax: { color: C.muted, fontSize: 18, fontWeight: "600" },
  summary: { color: C.sub, fontSize: 14, textAlign: "center", marginTop: 8 },

  metaRow: { flexDirection: "row", justifyContent: "space-between", backgroundColor: C.card, borderRadius: 12, padding: 14, borderWidth: 1, borderColor: C.border, marginBottom: 10 },
  metaLabel: { color: C.muted, fontSize: 11, fontWeight: "700", letterSpacing: 0.5 },
  metaValue: { color: C.text, fontSize: 14, fontWeight: "700" },
  payloadBox: { backgroundColor: C.card, borderRadius: 12, padding: 14, borderWidth: 1, borderColor: C.border, marginBottom: 16 },
  payloadText: { color: C.text, fontSize: 13, marginTop: 6, fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace" },

  indicators: { marginBottom: 18 },
  sectionTitle: { color: C.text, fontSize: 15, fontWeight: "700", marginBottom: 10 },
  indicatorRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", backgroundColor: C.input, borderRadius: 10, padding: 12, marginBottom: 8 },
  indicatorText: { color: C.sub, fontSize: 13, flex: 1, paddingRight: 10 },
  indicatorPts: { fontSize: 13, fontWeight: "800" },

  btnPrimary: { backgroundColor: C.accent, borderRadius: 12, paddingVertical: 15, alignItems: "center", marginTop: 6 },
  btnPrimaryText: { color: "#04121a", fontSize: 16, fontWeight: "800" },
  btnGhost: { borderWidth: 1.5, borderRadius: 12, paddingVertical: 14, alignItems: "center", marginTop: 12 },
  btnGhostText: { fontSize: 15, fontWeight: "700" },
  linkText: { color: C.sub, textAlign: "center", marginTop: 14, fontSize: 14 },

  modalBg: { flex: 1, backgroundColor: "rgba(0,0,0,0.6)", justifyContent: "center", padding: 24 },
  modalCard: { backgroundColor: C.card, borderRadius: 18, padding: 22, borderWidth: 1, borderColor: C.border },
  textInput: { backgroundColor: C.input, borderWidth: 1, borderColor: C.border, borderRadius: 10, color: C.text, padding: 14, fontSize: 14, marginBottom: 16 },
});
