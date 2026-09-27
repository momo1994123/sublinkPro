import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

// material-ui
import { useTheme } from '@mui/material/styles';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import Snackbar from '@mui/material/Snackbar';
import Stack from '@mui/material/Stack';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

// icons
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ClearIcon from '@mui/icons-material/Clear';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';

// project imports
import MainCard from 'ui-component/cards/MainCard';

// ==============================|| 解析引擎（纯函数） ||============================== //

const b64decode = (s) => {
  const norm = s.trim().replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(norm + '='.repeat((4 - (norm.length % 4)) % 4));
  // UTF-8 safe decode
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

const b64encode = (str) => {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
};

const parseQs = (qs) => {
  const out = {};
  new URLSearchParams(qs).forEach((v, k) => {
    out[k] = v;
  });
  return out;
};

/** v2rayN 老 vless: vless://b64(none:uuid@host:port)?remarks&obfs&obfsParam&path&tls&peer&sni */
const parseLegacyVless = (link) => {
  // 必须先剥离 #fragment，否则 remark 会被并进最后一个查询参数（如 peer=host#remark）
  const m = link.match(/^vless:\/\/([^?#]+)(?:\?([^#]*))?(?:#(.*))?$/);
  if (!m) return null;
  const [, userinfo, qs = '', hash = ''] = m;
  if (userinfo.includes('@')) return null; // 标准 vless，交给标准解析
  let decoded;
  try {
    decoded = b64decode(userinfo);
  } catch {
    return null;
  }
  // none:uuid@host:port
  const atIdx = decoded.lastIndexOf('@');
  if (atIdx < 0) return null;
  const [secUuid, hostport] = [decoded.slice(0, atIdx), decoded.slice(atIdx + 1)];
  const colonIdx = secUuid.indexOf(':');
  const enc = colonIdx >= 0 ? secUuid.slice(0, colonIdx) : 'none';
  const uuid = colonIdx >= 0 ? secUuid.slice(colonIdx + 1) : secUuid;
  const hp = hostport.lastIndexOf(':');
  if (hp < 0) return null;
  const host = hostport.slice(0, hp);
  const port = parseInt(hostport.slice(hp + 1), 10);
  if (!uuid || !host || !port) return null;

  const p = parseQs(qs);
  const obfs = (p.obfs || 'tcp').toLowerCase();
  const typeMap = { websocket: 'ws', ws: 'ws', tcp: 'tcp', grpc: 'grpc', httpupgrade: 'httpupgrade' };
  const net = typeMap[obfs] || obfs;
  const wsHost = p.obfsParam || p.host || '';
  const sni = p.peer || p.sni || p.host || wsHost || host;
  const tls = p.tls === '1' || p.tls === 'true';
  const name = p.remarks || p.remark || decodeURIComponent(hash) || `${host}:${port}`;

  const node = { name, protocol: 'vless', uuid, server: host, port, tls, network: net, udp: true };
  if (tls) {
    node.sni = sni;
    node['skip-cert-verify'] = false;
  }
  if (net === 'ws') {
    node['ws-path'] = p.path || '/';
    if (wsHost) node['ws-host'] = wsHost;
  }
  return node;
};

/** 标准 vless URI: vless://uuid@host:port?encryption&security&sni&type&host&path&flow#name */
const parseStdVless = (link) => {
  const m = link.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)?(?:#(.*))?$/);
  if (!m) return null;
  const [, uuid, server, portStr, qs = '', hash = ''] = m;
  const p = parseQs(qs);
  const name = decodeURIComponent(hash || `${server}:${portStr}`);
  const security = p.security || 'none';
  const tls = security === 'tls' || security === 'reality';
  const node = {
    name,
    protocol: 'vless',
    uuid,
    server,
    port: parseInt(portStr, 10),
    tls,
    network: p.type || 'tcp',
    udp: true
  };
  if (p.flow) node.flow = p.flow;
  if (tls) {
    node.sni = p.sni || server;
    if (security === 'reality') {
      node['reality-opts'] = { 'public-key': p.pbk || '' };
      if (p.sid) node['reality-opts']['short-id'] = p.sid;
    }
  }
  if (p.type === 'ws') {
    node['ws-path'] = p.path || '/';
    if (p.host) node['ws-host'] = p.host;
  }
  if (p.type === 'grpc') node['grpc-service-name'] = p.serviceName || '';
  return node;
};

/** vmess（标准 base64 JSON，兼容 v2rayN 变体字段） */
const parseVmess = (link) => {
  let json;
  try {
    json = JSON.parse(b64decode(link.replace(/^vmess:\/\//, '')));
  } catch {
    return null;
  }
  const port = parseInt(json.port, 10);
  if (!json.add || !port || !json.id) return null;
  const tls = json.tls === 'tls' || json.tls === 'reality';
  const node = {
    name: json.ps || `${json.add}:${port}`,
    protocol: 'vmess',
    uuid: json.id,
    alterId: parseInt(json.aid ?? json.alterId ?? 0, 10) || 0,
    cipher: json.scy || json.security || 'auto',
    server: json.add,
    port,
    tls,
    network: json.net || 'tcp',
    udp: true
  };
  if (tls && json.sni) node.sni = json.sni;
  if (json.net === 'ws') {
    node['ws-path'] = json.path || '/';
    if (json.host) node['ws-host'] = json.host;
  }
  if (json.net === 'grpc') node['grpc-service-name'] = json.path || '';
  return node;
};

/** ss: 兼容标准 SIP002 与老式 base64(method:pass@host:port) */
const parseSs = (link) => {
  const m = link.match(/^ss:\/\/([^?#]+)(?:\?([^#]*))?(?:#(.*))?$/);
  if (!m) return null;
  const [, main, qs = '', hash = ''] = m;
  const name = decodeURIComponent(hash || '');
  const plugin = parseQs(qs).plugin || '';
  let method;
  let password;
  let server;
  let port;
  let userInfo = main.split('@')[0];
  const hostPart = main.includes('@') ? main.slice(main.indexOf('@') + 1) : null;
  try {
    userInfo = b64decode(userInfo);
  } catch {
    /* userInfo 可能本就是明文 */
  }
  if (hostPart) {
    // SIP002: b64(method:pass)@host:port 或明文
    const hp = hostPart.lastIndexOf(':');
    server = hostPart.slice(0, hp);
    port = parseInt(hostPart.slice(hp + 1), 10);
    const cIdx = userInfo.indexOf(':');
    if (cIdx < 0) return null;
    method = userInfo.slice(0, cIdx);
    password = userInfo.slice(cIdx + 1);
  } else {
    // 全 base64 老式: method:pass@host:port
    const at = userInfo.lastIndexOf('@');
    if (at < 0) return null;
    const mp = userInfo.slice(0, at);
    const hp = userInfo.slice(at + 1);
    const cIdx = mp.indexOf(':');
    const hIdx = hp.lastIndexOf(':');
    if (cIdx < 0 || hIdx < 0) return null;
    method = mp.slice(0, cIdx);
    password = mp.slice(cIdx + 1);
    server = hp.slice(0, hIdx);
    port = parseInt(hp.slice(hIdx + 1), 10);
  }
  if (!method || !server || !port) return null;
  const node = { name: name || `${server}:${port}`, protocol: 'ss', cipher: method, password, server, port, udp: true };
  if (plugin.includes('obfs-local')) {
    const pm = plugin.match(/obfs=([^;]+)/);
    const hm = plugin.match(/obfs-host=([^;]+)/);
    if (pm) node.plugin = 'obfs';
    if (pm) node['plugin-opts'] = { mode: pm[1], ...(hm ? { host: hm[1] } : {}) };
  }
  return node;
};

/** trojan 标准 URI */
const parseTrojan = (link) => {
  const m = link.match(/^trojan:\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)?(?:#(.*))?$/);
  if (!m) return null;
  const [, password, server, portStr, qs = '', hash = ''] = m;
  const p = parseQs(qs);
  const node = {
    name: decodeURIComponent(hash || `${server}:${portStr}`),
    protocol: 'trojan',
    password,
    server,
    port: parseInt(portStr, 10),
    udp: true,
    sni: p.sni || p.peer || server,
    'skip-cert-verify': p.allowInsecure === '1'
  };
  if (p.type === 'ws') {
    node.network = 'ws';
    node['ws-path'] = p.path || '/';
    if (p.host) node['ws-host'] = p.host;
  }
  return node;
};

/** hysteria2 / hy2 */
const parseHy2 = (link) => {
  const m = link.match(/^hy2:\/\/([^@?]+)@([^:]+):(\d+)\??([^#]*)?(?:#(.*))?$/);
  if (!m) return null;
  const [, auth, server, portStr, qs = '', hash = ''] = m;
  const p = parseQs(qs);
  return {
    name: decodeURIComponent(hash || `${server}:${portStr}`),
    protocol: 'hysteria2',
    auth: decodeURIComponent(auth),
    server,
    port: parseInt(portStr, 10),
    sni: p.sni || server,
    'skip-cert-verify': p.insecure === '1',
    udp: true
  };
};

/** socks/http 裸链接（Shadowrocket 也导出这种） */
const parseSocksHttp = (link) => {
  const m = link.match(/^(socks5?|https?):\/\/(?:([^:@]+)(?::([^@]*))?@)?([^:@/]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$/i);
  if (!m) return null;
  const [, scheme, user, pass, server, portStr, qs = '', hash = ''] = m;
  const p = parseQs(qs);
  const proto = scheme.toLowerCase() === 'https' || scheme.toLowerCase() === 'http' ? 'http' : 'socks5';
  return {
    name: decodeURIComponent(hash || p.remarks || `${server}:${portStr}`),
    protocol: proto,
    server,
    port: parseInt(portStr, 10),
    ...(user ? { username: decodeURIComponent(user), password: decodeURIComponent(pass || '') } : {}),
    ...(proto === 'http' && scheme.toLowerCase() === 'https' ? { tls: true } : {}),
    udp: proto === 'socks5'
  };
};

/** Shadowrocket/小火箭导出的行式格式: host:port method:password remarks 之类兜底解析 */
const parseShadowrocketLine = (line) => {
  // ss 裸行: host:port method:password#remarks 或 host:port method:password 备注
  const m = line.match(/^(\[[^\]]+\]|[^:\s]+):(\d+)\s+(\S+)\s+(\S+)(?:\s+(?:#|\/\/)?\s*(.+))?$/);
  if (!m) return null;
  const [, server, portStr, method, password, remark] = m;
  if (!/^(aes|chacha|rc4|none|2022)/i.test(method)) return null;
  return {
    name: (remark || `${server}:${portStr}`).trim(),
    protocol: 'ss',
    cipher: method,
    password,
    server,
    port: parseInt(portStr, 10),
    udp: true
  };
};

const convertLine = (line) => {
  const t = line.trim();
  if (!t || t.startsWith('#') || t.startsWith('//')) return { status: 'skip' };
  try {
    if (/^vless:\/\//i.test(t)) {
      const node = parseLegacyVless(t) || parseStdVless(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'vless 解析失败' };
    }
    if (/^vmess:\/\//i.test(t)) {
      const node = parseVmess(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'vmess 解析失败' };
    }
    if (/^ss:\/\//i.test(t)) {
      const node = parseSs(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'ss 解析失败' };
    }
    if (/^(trojan):\/\//i.test(t)) {
      const node = parseTrojan(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'trojan 解析失败' };
    }
    if (/^(hysteria2|hy2):\/\//i.test(t)) {
      const node = parseHy2(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'hysteria2 解析失败' };
    }
    if (/^socks5?(?::\/\/)/i.test(t) || /^https?:\/\/[^/]+:\d+/.test(t)) {
      if (/^https?:\/\/(127\.|localhost|192\.168\.|10\.)/i.test(t)) return { status: 'skip' };
      const node = parseSocksHttp(t);
      return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: 'socks/http 解析失败' };
    }
    const node = parseShadowrocketLine(t);
    return node ? { status: 'ok', node, original: t } : { status: 'error', original: t, reason: '无法识别的格式' };
  } catch (e) {
    return { status: 'error', original: t, reason: String(e) };
  }
};

// ==============================|| Clash YAML 生成 ||============================== //

const yamlStr = (v) => {
  if (v === null || v === undefined) return '""';
  const s = String(v);
  return /^[\w.-]+$/.test(s) && s.length > 0 ? s : JSON.stringify(s);
};

const nodeToClash = (n) => {
  const out = [];
  out.push(`  - name: ${yamlStr(n.name)}`);
  if (n.protocol === 'ss') {
    out.push(`    type: ss`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    out.push(`    cipher: ${yamlStr(n.cipher)}`);
    out.push(`    password: ${yamlStr(n.password)}`);
    out.push(`    udp: ${!!n.udp}`);
    if (n.plugin) {
      out.push(`    plugin: obfs`);
      out.push(`    plugin-opts:`);
      out.push(`      mode: ${yamlStr(n['plugin-opts']?.mode)}`);
      if (n['plugin-opts']?.host) out.push(`      host: ${yamlStr(n['plugin-opts'].host)}`);
    }
  } else if (n.protocol === 'vmess') {
    out.push(`    type: vmess`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    out.push(`    uuid: ${yamlStr(n.uuid)}`);
    out.push(`    alterId: ${n.alterId || 0}`);
    out.push(`    cipher: ${yamlStr(n.cipher || 'auto')}`);
    out.push(`    udp: ${!!n.udp}`);
    if (n.tls) out.push(`    tls: true`);
    if (n.sni) out.push(`    servername: ${yamlStr(n.sni)}`);
    out.push(`    network: ${yamlStr(n.network || 'tcp')}`);
    if (n.network === 'ws') {
      out.push(`    ws-opts:`);
      out.push(`      path: ${yamlStr(n['ws-path'] || '/')}`);
      if (n['ws-host']) out.push(`      headers:\n        Host: ${yamlStr(n['ws-host'])}`);
    }
  } else if (n.protocol === 'vless') {
    out.push(`    type: vless`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    out.push(`    uuid: ${yamlStr(n.uuid)}`);
    out.push(`    udp: ${!!n.udp}`);
    if (n.tls) out.push(`    tls: true`);
    if (n.sni) out.push(`    servername: ${yamlStr(n.sni)}`);
    if (n.flow) out.push(`    flow: ${yamlStr(n.flow)}`);
    if (n['reality-opts']) {
      out.push(`    reality-opts:`);
      out.push(`      public-key: ${yamlStr(n['reality-opts']['public-key'])}`);
      if (n['reality-opts']['short-id']) out.push(`      short-id: ${yamlStr(n['reality-opts']['short-id'])}`);
    }
    out.push(`    network: ${yamlStr(n.network || 'tcp')}`);
    if (n.network === 'ws') {
      out.push(`    ws-opts:`);
      out.push(`      path: ${yamlStr(n['ws-path'] || '/')}`);
      if (n['ws-host']) out.push(`      headers:\n        Host: ${yamlStr(n['ws-host'])}`);
    }
    if (n.network === 'grpc') out.push(`    grpc-opts:\n      grpc-service-name: ${yamlStr(n['grpc-service-name'] || '')}`);
  } else if (n.protocol === 'trojan') {
    out.push(`    type: trojan`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    out.push(`    password: ${yamlStr(n.password)}`);
    out.push(`    udp: ${!!n.udp}`);
    if (n.sni) out.push(`    sni: ${yamlStr(n.sni)}`);
    out.push(`    skip-cert-verify: ${!!n['skip-cert-verify']}`);
    if (n.network === 'ws') {
      out.push(`    network: ws`);
      out.push(`    ws-opts:`);
      out.push(`      path: ${yamlStr(n['ws-path'] || '/')}`);
      if (n['ws-host']) out.push(`      headers:\n        Host: ${yamlStr(n['ws-host'])}`);
    }
  } else if (n.protocol === 'hysteria2') {
    out.push(`    type: hysteria2`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    out.push(`    auth: ${yamlStr(n.auth)}`);
    if (n.sni) out.push(`    sni: ${yamlStr(n.sni)}`);
    out.push(`    skip-cert-verify: ${!!n['skip-cert-verify']}`);
  } else if (n.protocol === 'socks5') {
    out.push(`    type: socks5`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    if (n.username) {
      out.push(`    username: ${yamlStr(n.username)}`);
      out.push(`    password: ${yamlStr(n.password)}`);
    }
    out.push(`    udp: ${!!n.udp}`);
  } else if (n.protocol === 'http') {
    out.push(`    type: http`);
    out.push(`    server: ${yamlStr(n.server)}`);
    out.push(`    port: ${n.port}`);
    if (n.username) {
      out.push(`    username: ${yamlStr(n.username)}`);
      out.push(`    password: ${yamlStr(n.password)}`);
    }
    if (n.tls) out.push(`    tls: true`);
  }
  return out.join('\n');
};

/** 标准 URI 再生成 */
const nodeToUri = (n) => {
  const tag = encodeURIComponent(n.name);
  if (n.protocol === 'vless') {
    const q = new URLSearchParams();
    q.set('encryption', 'none');
    if (n.tls) {
      q.set('security', 'tls');
      q.set('sni', n.sni || n.server);
    } else {
      q.set('security', 'none');
    }
    q.set('type', n.network || 'tcp');
    if (n.network === 'ws') {
      if (n['ws-host']) q.set('host', n['ws-host']);
      q.set('path', n['ws-path'] || '/');
    }
    if (n.network === 'grpc') q.set('serviceName', n['grpc-service-name'] || '');
    if (n.flow) q.set('flow', n.flow);
    return `vless://${n.uuid}@${n.server}:${n.port}?${q.toString()}#${tag}`;
  }
  if (n.protocol === 'vmess') {
    const json = {
      v: '2',
      ps: n.name,
      add: n.server,
      port: String(n.port),
      id: n.uuid,
      aid: String(n.alterId || 0),
      scy: n.cipher || 'auto',
      net: n.network || 'tcp',
      type: 'none',
      host: n['ws-host'] || '',
      path: n['ws-path'] || '',
      tls: n.tls ? 'tls' : '',
      sni: n.sni || '',
      udp: n.udp ? true : false
    };
    return `vmess://${b64encode(JSON.stringify(json))}`;
  }
  if (n.protocol === 'ss') {
    const userinfo = b64encode(`${n.cipher}:${n.password}`);
    return `ss://${userinfo}@${n.server}:${n.port}#${tag}`;
  }
  if (n.protocol === 'trojan') {
    const q = new URLSearchParams();
    if (n.sni) q.set('sni', n.sni);
    return `trojan://${encodeURIComponent(n.password)}@${n.server}:${n.port}?${q.toString()}#${tag}`;
  }
  if (n.protocol === 'hysteria2') {
    const q = new URLSearchParams();
    if (n.sni) q.set('sni', n.sni);
    return `hy2://${encodeURIComponent(n.auth)}@${n.server}:${n.port}?${q.toString()}#${tag}`;
  }
  if (n.protocol === 'socks5' || n.protocol === 'http') {
    const auth = n.username ? `${encodeURIComponent(n.username)}:${encodeURIComponent(n.password || '')}@` : '';
    return `${n.protocol}://${auth}${n.server}:${n.port}#${tag}`;
  }
  return null;
};

// ==============================|| 转换器页面 ||============================== //

const Converter = () => {
  const theme = useTheme();
  const { t } = useTranslation();
  const [input, setInput] = useState('');
  const [tab, setTab] = useState(0);
  const [snack, setSnack] = useState({ open: false, msg: '' });

  const results = useMemo(() => {
    const lines = input.split('\n');
    return lines.map(convertLine);
  }, [input]);

  const okList = results.filter((r) => r.status === 'ok');
  const errList = results.filter((r) => r.status === 'error');

  const uriText = useMemo(() => okList.map((r) => nodeToUri(r.node)).filter(Boolean).join('\n'), [okList]);
  const yamlText = useMemo(
    () => (okList.length ? 'proxies:\n' + okList.map((r) => nodeToClash(r.node)).join('\n') : ''),
    [okList]
  );

  const copy = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text);
      setSnack({ open: true, msg: `${label} 已复制 ${okList.length} 条` });
    } catch {
      setSnack({ open: true, msg: '复制失败，请手动选择文本复制' });
    }
  };

  return (
    <MainCard title={t('converter.page.title')}>
      <Stack spacing={2}>
        <Alert severity="info" variant="outlined">
          {t('converter.page.hint')}
        </Alert>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Stack spacing={1}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="subtitle1">{t('converter.input.title')}</Typography>
                <Button size="small" startIcon={<ClearIcon />} onClick={() => setInput('')} disabled={!input}>
                  {t('converter.input.clear')}
                </Button>
              </Stack>
              <TextField
                multiline
                fullWidth
                minRows={16}
                maxRows={28}
                placeholder={t('converter.input.placeholder')}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                sx={{ '& textarea': { fontFamily: 'monospace', fontSize: 13 } }}
              />
            </Stack>
          </Grid>
          <Grid item xs={12} md={6}>
            <Stack spacing={1}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Tabs value={tab} onChange={(e, v) => setTab(v)} aria-label="output tabs">
                  <Tab label={t('converter.output.tabUri')} />
                  <Tab label={t('converter.output.tabClash')} />
                </Tabs>
                <Box>
                  {tab === 0 ? (
                    <IconButton onClick={() => copy(uriText, t('converter.output.tabUri'))} disabled={!uriText} size="small">
                      <ContentCopyIcon />
                    </IconButton>
                  ) : (
                    <IconButton onClick={() => copy(yamlText, t('converter.output.tabClash'))} disabled={!yamlText} size="small">
                      <ContentCopyIcon />
                    </IconButton>
                  )}
                </Box>
              </Stack>
              <TextField
                multiline
                fullWidth
                minRows={16}
                maxRows={28}
                value={tab === 0 ? uriText : yamlText}
                InputProps={{
                  readOnly: true,
                  endAdornment: okList.length > 0 && (
                    <InputAdornment position="start" sx={{ alignSelf: 'flex-start', mt: 1 }} />
                  )
                }}
                sx={{ '& textarea': { fontFamily: 'monospace', fontSize: 13 } }}
                placeholder={t('converter.output.placeholder')}
              />
            </Stack>
          </Grid>
        </Grid>

        <Stack direction="row" spacing={2} alignItems="center">
          <SwapHorizIcon color="primary" />
          <Typography variant="body2">
            {t('converter.stats.ok', { count: okList.length })} ·{' '}
            {errList.length > 0 ? (
              <Typography component="span" color="error.main">
                {t('converter.stats.error', { count: errList.length })}
              </Typography>
            ) : (
              t('converter.stats.noError')
            )}
          </Typography>
        </Stack>

        {errList.length > 0 && (
          <Alert severity="warning">
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
              {errList
                .slice(0, 10)
                .map((r) => `✗ ${r.reason}: ${r.original.slice(0, 80)}`)
                .join('\n')}
            </Typography>
          </Alert>
        )}
      </Stack>
      <Snackbar
        open={snack.open}
        autoHideDuration={2000}
        message={snack.msg}
        onClose={() => setSnack((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      />
    </MainCard>
  );
};

export default Converter;
