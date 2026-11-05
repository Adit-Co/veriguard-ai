import type {
  AsnInfo,
  DnsRecordSet,
  HttpResponseInfo,
  IntermediaryAssessment,
  IntermediarySignal,
} from './types.js'

const CNAME_MARKERS: Array<{ suffix: string; label: string }> = [
  { suffix: '.cdn.cloudflare.net', label: 'Cloudflare' },
  { suffix: '.cloudflare.net', label: 'Cloudflare' },
  { suffix: '.cloudflareinsights.com', label: 'Cloudflare' },
  { suffix: '.d7cdn.net', label: 'Cloudflare' },
  { suffix: '.doh-web.com', label: 'Cloudflare' },
  { suffix: '.awsdns', label: 'Amazon Route 53 / AWS' },
  { suffix: '.cloudfront.net', label: 'Amazon CloudFront' },
  { suffix: '.akamaized.net', label: 'Akamai' },
  { suffix: '.edgesuite.net', label: 'Akamai' },
  { suffix: '.edgekey.net', label: 'Akamai' },
  { suffix: '.fastly.net', label: 'Fastly' },
  { suffix: '.fastlylb.net', label: 'Fastly' },
  { suffix: '.azureedge.net', label: 'Microsoft Azure Front Door' },
  { suffix: '.azurefd.net', label: 'Microsoft Azure Front Door' },
  { suffix: '.cdn77.org', label: 'CDN77' },
  { suffix: '.impervadns.net', label: 'Imperva' },
  { suffix: '.incapdns.net', label: 'Imperva' },
  { suffix: '.edgecastcdn.net', label: 'EdgeCast/Verizon' },
  { suffix: '.mncdn.com', label: 'MediaChain' },
  { suffix: '.b21ts.cn', label: 'Baishan CDN' },
  { suffix: '.cdngc.net', label: 'CDNetworks' },
]

const NS_MARKERS: Array<{ suffix: string; label: string }> = [
  { suffix: '.ns.cloudflare.com', label: 'Cloudflare' },
  { suffix: 'ns1-domain-connect.net', label: 'Domain.com DNS' },
  { suffix: '.cloudflare.com', label: 'Cloudflare' },
  { suffix: '.cfar.me', label: 'Cloudflare Registrar' },
  { suffix: '.awsdns-0', label: 'Amazon Route 53' },
  { suffix: '.googledomains.com', label: 'Google Cloud DNS' },
  { suffix: '.gsdns.io', label: 'Google Squared DNS' },
  { suffix: '.azure-dns.com', label: 'Microsoft Azure DNS' },
  { suffix: '.impervadns.net', label: 'Imperva' },
  { suffix: '.sedoparking.com', label: 'Layanan parkir domain' },
  { suffix: '.afternic.com', label: 'Layanan parkir domain' },
]

const ASN_MARKERS: Array<{ needle: string; label: string }> = [
  { needle: 'cloudflare, inc.', label: 'Cloudflare' },
  { needle: 'as13335', label: 'Cloudflare' },
  { needle: 'akamai technologies', label: 'Akamai' },
  { needle: 'fastly', label: 'Fastly' },
  { needle: 'amazon.com, inc.', label: 'AWS' },
  { needle: 'microsoft corporation', label: 'Microsoft' },
  { needle: 'google llc', label: 'Google' },
  { needle: 'stackpath', label: 'StackPath' },
  { needle: 'imperva', label: 'Imperva' },
]

const PROXY_HEADER_MARKERS: Array<{ needle: string; label: string }> = [
  { needle: 'cloudflare', label: 'Cloudflare' },
  { needle: 'akamai', label: 'Akamai' },
  { needle: 'fastly', label: 'Fastly' },
  { needle: 'ecs', label: 'EdgeCast/Verizon' },
  { needle: 'varnish', label: 'Varnish (reverse proxy)' },
  { needle: 'nginx-proxy', label: 'nginx (proxy)' },
  { needle: 'traefik', label: 'Traefik (reverse proxy)' },
  { needle: 'bunnycdn', label: 'BunnyCDN' },
]

function endsWithMarker(value: string, markers: Array<{ suffix: string; label: string }>): string | null {
  const normalized = value.toLowerCase().replace(/\.$/, '')
  for (const marker of markers) {
    if (normalized.endsWith(marker.suffix.toLowerCase())) return marker.label
  }
  return null
}

const MAX_SIGNALS = 6
const MAX_EVIDENCE_PER_LABEL = 3
const SIGNAL_TEXT_LIMIT = 280

function joinEvidence(parts: string[]): string {
  const text = parts.join(' ')
  if (text.length <= SIGNAL_TEXT_LIMIT) return text
  const clipped = text.slice(0, SIGNAL_TEXT_LIMIT)
  const stop = Math.max(clipped.lastIndexOf('. '), clipped.lastIndexOf('.'))
  return (stop > 60 ? clipped.slice(0, stop + 1) : `${clipped}…`).trim()
}

export function assessIntermediary(
  dns: DnsRecordSet[],
  response: HttpResponseInfo,
  asn: AsnInfo | null,
): IntermediaryAssessment {
  // Satu label hanya boleh muncul sekali; bukti DNS, header, dan ASN digabung.
  const evidenceByLabel = new Map<string, string[]>()

  const push = (label: string, evidence: string): void => {
    const existing = evidenceByLabel.get(label)
    if (existing) {
      if (existing.length < MAX_EVIDENCE_PER_LABEL && !existing.includes(evidence)) {
        existing.push(evidence)
      }
      return
    }
    if (evidenceByLabel.size >= MAX_SIGNALS) return
    evidenceByLabel.set(label, [evidence])
  }

  // Urutan prioritas bukti: header respons (paling langsung), CNAME, kepemilikan ASN, baru nameserver.
  for (const header of response.headers) {
    const value = header.value.toLowerCase()
    if (header.name === 'server' || header.name === 'via' || header.name.startsWith('x-')) {
      for (const marker of PROXY_HEADER_MARKERS) {
        if (value.includes(marker.needle)) {
          push(marker.label, `Header respons \`${header.name}: ${header.value}\`.`)
        }
      }
    }
    if (header.name === 'cf-ray' || header.name === 'cf-cache-status') {
      push('Cloudflare', `Header respons \`${header.name}\` khas perantara CDN.`)
    }
    if (header.name === 'via') {
      push('Perantara/penyeimbang beban', `Header \`via: ${header.value}\` menandai hop perantara.`)
    }
  }

  const cname = dns.find((entry) => entry.type === 'CNAME')
  for (const record of cname?.lookup.value ?? []) {
    const label = endsWithMarker(record, CNAME_MARKERS)
    if (label) push(label, `Rekor CNAME mengarah ke ${record}.`)
  }

  const asnText = `${asn?.organization ?? ''} ${asn?.asn ?? ''}`.toLowerCase()
  for (const marker of ASN_MARKERS) {
    if (asnText.includes(marker.needle)) {
      push(
        marker.label,
        `Kepemilikan jaringan ${asn?.organization ?? asn?.asn ?? 'ASN'} pada alamat hasil resolusi.`,
      )
    }
  }

  const ns = dns.find((entry) => entry.type === 'NS')
  const nsHosts = ns?.lookup.value ?? []
  for (const marker of NS_MARKERS) {
    const matched = nsHosts.filter((host) =>
      host.toLowerCase().replace(/\.$/, '').endsWith(marker.suffix.toLowerCase()),
    )
    if (matched.length > 0) {
      push(
        marker.label,
        `Nameserver dikelola ${marker.label} (${matched.slice(0, 2).join(', ')}).`,
      )
    }
  }

  const signals: IntermediarySignal[] = [...evidenceByLabel.entries()].map(([label, evidence]) => ({
    label,
    evidence: joinEvidence(evidence),
  }))
  const hasAnySignal = signals.length > 0
  const unavailable =
    dns.every((entry) => entry.lookup.status === 'failed' || entry.lookup.status === 'unavailable') &&
    response.headers.length === 0

  if (unavailable) {
    return {
      state: 'unavailable',
      signals: [],
      note: 'Belum ada cukup data DNS atau header untuk menilai adanya perantara.',
    }
  }

  if (!hasAnySignal) {
    return {
      state: 'no_signal',
      signals: [],
      note: 'Tidak ada sinyal CDN/proxy pada DNS, header, dan ASN. Ini bukan bukti bahwa alamat hasil resolusi adalah server asal.',
    }
  }

  return {
    state: 'possible',
    signals,
    note: 'Terdapat sinyal CDN, proxy, atau penyeimbang beban. Alamat IP yang tampil mungkin milik perantara tersebut, bukan server asal. VERIGUARD tidak mencoba menemukan atau menembus infrastruktur asal.',
  }
}
