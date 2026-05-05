<template>
    <div>
        <div v-if="results">
            <div v-if="grep_keyword('STALKERWARE', 'high')" class="high-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.stalkerware_msg')"></h1>
                    <div class="report-actions">
                        <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                        <button class="btn btn-report-high" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                    </div>
                </div>
            </div>
            <div v-else-if="alerts.high.length >= 1" class="high-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.high_msg', { nb: alertCountWord('high') })"></h1>
                    <div class="report-actions">
                        <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                        <button class="btn btn-report-high" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                    </div>
                </div>
            </div>
            <div v-else-if="alerts.moderate.length >= 1" class="med-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.moderate_msg', { nb: alertCountWord('moderate') })"></h1>
                    <div class="report-actions">
                        <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                        <button class="btn btn-report-moderate" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                    </div>
                </div>
            </div>
            <div v-else-if="alerts.low.length >= 1" class="low-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.low_msg', { nb: alertCountWord('low') })"></h1>
                    <div class="report-actions">
                        <button class="btn btn-report-low-light" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                        <button class="btn btn-report-low" @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                    </div>
                </div>
            </div>
            <div v-else class="none-wrapper">
                <div class="center">
                    <h1 class="warning-title" v-html="$t('report.fine_msg')"></h1>
                    <div class="report-actions">
                        <button class="btn btn-report-low-light"  @click="show_report=true;results=false;">{{ $t("report.show_full_report") }}</button>
                        <button class="btn btn-report-low" v-on:click="new_capture()">{{ $t("report.start_new_capture") }}</button>
                    </div>
                </div>
            </div>
        </div>
        <div v-else-if="show_report" class="wrapper">
            <div class="report-wrapper">
                <div class="device-ctx">
                    <h3 style="margin: 0; padding-left:10px; margin-bottom:10px">{{ $t("report.report_of") }} {{ device && device.name ? device.name : "—" }}</h3>
                    <div class="apcard-frame apcard-frame--wide">
                        <div class="device-ctx-legend">
                            <div class="alert-body">
                                {{ $t("report.pcap_sha1") }} {{ pcapField("SHA1") }}<br />
                                {{ $t("report.capture_started") }} {{ pcapTimeFirst("First packet time") }}<br />
                                {{ $t("report.capture_ended") }} {{ pcapTimeFirst("Last packet time") }}<br />
                                {{ $t("report.detection_methods") }} {{ detection_methods }}
                            </div>
                        </div>
                    </div>
                    <div class="analysis-health" v-if="analysis_meta && analysis_meta.degraded">
                        <strong>{{ $t("report.analysis_health_title") }}</strong><br />
                        <span v-if="analysis_meta.internet === false">
                            {{ $t("report.analysis_health_offline", { lost: analysis_meta.lost_pct, eff: analysis_meta.effectiveness_pct }) }}
                        </span>
                        <span v-else>
                            <template v-if="failedExternalChecksLabel">
                                {{ $t("report.analysis_health_degraded_with_checks", { checks: failedExternalChecksLabel, lost: analysis_meta.lost_pct, eff: analysis_meta.effectiveness_pct }) }}
                            </template>
                            <template v-else>
                                {{ $t("report.analysis_health_degraded", { lost: analysis_meta.lost_pct, eff: analysis_meta.effectiveness_pct }) }}
                            </template>
                        </span>
                    </div>
                </div>
                <div v-if="alerts">
                    <h5 class="title-report" v-if="grouped_alerts.length>0">{{ $t("report.alerts_table") }}</h5>
                    <ul class="alerts">
                        <li class="alert" v-for="group in grouped_alerts" :key="group.host">
                            <details class="alert-group" open>
                                <summary class="alert-group-summary">
                                    <span class="title">
                                        {{ hostTitlePrefix(group.host) }}{{ group.host }}
                                        <span class="host-services" v-if="group.service_summary"> - {{ group.service_summary }}</span>
                                    </span>
                                    <span class="alert-group-count">
                                        <span class="high-label-head" v-if="group.counts.high">{{ group.counts.high }} {{ $t("report.high") }}</span>
                                        <span class="moderate-label-head" v-if="group.counts.moderate">{{ group.counts.moderate }} {{ $t("report.moderate") }}</span>
                                        <span class="low-label-head" v-if="group.counts.low">{{ group.counts.low }} {{ $t("report.low") }}</span>
                                    </span>
                                    <span class="btn-whitelist" v-on:click.stop="add_whitelist(group.host)">Add to the whitelist</span>
                                </summary>
                                <div class="block-alerts">
                                    <div v-if="group.alerts.high.length">
                                        <div class="alert" v-for="alert in group.alerts.high" :key="alertKey(alert)">
                                            <div class="alert-header">
                                                <span class="high-label">{{ $t("report.high") }}</span>
                                                <span class="alert-id">{{ alert.id }}</span>
                                            </div>
                                            <div class="alert-body">
                                                <span class="title">{{ alert.title }}</span>
                                                <p class="description">{{ alert.description }}</p>
                                            </div>
                                        </div>
                                    </div>

                                    <div v-if="group.alerts.moderate.length">
                                        <div class="alert" v-for="alert in group.alerts.moderate" :key="alertKey(alert)">
                                            <div class="alert-header">
                                                <span class="moderate-label">{{ $t("report.moderate") }}</span>
                                                <span class="alert-id">{{ alert.id }}</span>
                                            </div>
                                            <div class="alert-body">
                                                <span class="title">{{ alert.title }}</span>
                                                <p class="description">{{ alert.description }}</p>
                                            </div>
                                        </div>
                                    </div>

                                    <div v-if="group.alerts.low.length">
                                        <div class="alert" v-for="alert in group.alerts.low" :key="alertKey(alert)">
                                            <div class="alert-header">
                                                <span class="low-label">{{ $t("report.low") }}</span>
                                                <span class="alert-id">{{ alert.id }}</span>
                                            </div>
                                            <div class="alert-body">
                                                <span class="title">{{ alert.title }}</span>
                                                <p class="description">{{ alert.description }}</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </details>
                        </li>
                    </ul>
                </div>
                <div class="no-alerts-to-show" v-else>
                    <span class="main-text">{{ $t("report.no_alerts_title") }}</span><br />
                    <span class="second-text">{{ $t("report.no_alerts_subtext") }}</span>
                </div>
                <h5 class="title-report" v-if="uncategorized_records.length>0">{{ $t("report.uncat_coms_table") }}</h5>
                <div v-if="uncategorized_records.length>0" class="apcard-frame apcard-frame--wide">
                    <table class="table-uncat">
                        <thead>
                            <tr>
                                <td>{{ $t("report.protocol") }}</td>
                                <td>{{ $t("report.domain_name") }}</td>
                                <td>{{ $t("report.ip_address") }}</td>
                                <td>{{ $t("report.port") }}</td>
                            </tr>
                        </thead>
                        <tr v-for="record in uncategorized_records" :key="record.ip_dst">
                            <td>{{ formatProtocolNames(record) }}</td>
                            <td v-on:click="add_whitelist((record.domains || [])[0])">
                                <span v-for="(part, idx) in formatDomainsWithUmbrellaRankParts(record)" :key="idx" :class="part.cls">{{ part.text }}</span>
                            </td>
                            <td v-on:click="add_whitelist(record.ip_dst)">{{ formatIpShort(record.ip_dst) }}</td>
                            <td>{{ formatRecordPorts(record) }}</td>
                        </tr>
                    </table>
                </div>
                <h5 class="title-report" v-if="whitelisted_records.length>0">{{ $t("report.whitelisted_coms_table") }}</h5>
                <div v-if="whitelisted_records.length>0" class="apcard-frame apcard-frame--wide">
                    <table class="table-uncat">
                        <thead>
                            <tr>
                                <td>{{ $t("report.protocol") }}</td>
                                <td>{{ $t("report.domain_name") }}</td>
                                <td>{{ $t("report.ip_address") }}</td>
                                <td>{{ $t("report.port") }}</td>
                            </tr>
                        </thead>
                        <tr v-for="record in whitelisted_records" :key="record.ip_dst">
                            <td>{{ formatProtocolNames(record) }}</td>
                            <td>{{ (record.domains || []).join(", ") }}</td>
                            <td>{{ formatIpShort(record.ip_dst) }}</td>
                            <td>{{ formatRecordPorts(record) }}</td>
                        </tr>
                    </table>
                </div>
                <div id="controls-analysis">
                    <div class="column col-6">
                        <button class="btn btn btn-primary width-100" v-on:click="save_capture()">{{ $t("report.export_report") }}</button>
                    </div>
                    <div class="column col-6">
                        <button class="btn width-100" @click="$router.push({ name: 'generate-ap' })">{{ $t("report.start_new_capture") }}</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>


<style>
#app {
    overflow-y: visible;
}   

.alert-group {
    width: 100%;
}

.alert-group-summary {
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    padding: 6px;
    background-color:#fbfbfb;
}

.alert-group-summary .title {
    font-weight: 600;
    display: inline-flex;
    align-items: baseline;
    gap: 6px;
}

.host-services {
    font-weight: 500;
    color: #7a7a7a;
}

.muted-rank {
    color: #b8b8b8;
}

.analysis-health {
    margin-top: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    background: #fff6e5;
    border: 1px solid rgba(255, 126, 51, 0.35);
    color: #5a3a21;
    font-size: 0.95em;
    line-height: 1.25em;
}

.alert-group-count {
    display: inline-flex;
    gap: 8px;
    height:20px;
    margin-left: auto;
    margin-right: 10px;
    font-size: 0.9em;
    opacity: 0.95;
}

.low-label-head {
    background-color: #4fce0eb8;
    padding: 3px 5px;
    text-transform: uppercase;
    font-size: 10px;
    font-weight: bold;
    border-radius: 5px;
    color: #fff;
}

.moderate-label-head {
    background-color: #ff7e33eb;
    padding: 3px 5px;
    text-transform: uppercase;
    font-size: 10px;
    font-weight: bold;
    border-radius: 5px;
    color: #fff;
}

.high-label-head {
    background-color: #e53d38;
    padding: 3px 5px;
    text-transform: uppercase;
    font-size: 10px;
    font-weight: bold;
    border-radius: 5px;
    color: #fff;
}

.alert-subheader {
    margin: 8px 0 4px;
    font-weight: 600;
}
</style>

<script>
import router from '../router'
import axios from 'axios'
import { bus } from "@/bus"

export default {
    name: 'report',   
    data() {
        return {
            results: true,
            show_report: false,
            detection_methods: "",
            uncategorized_records: [],
            whitelisted_records: [],
            device: null,
            methods: null,
            pcap: null,
            records: [],
            alerts: { high: [], moderate: [], low: [] },
            analysis_meta: null
        }
    },
    computed: {
        failedExternalChecksLabel: function() {
            try {
                var meta = this.analysis_meta || {}
                var checks = meta.checks || {}
                var names = Object.keys(checks).filter(function (k) {
                    var c = checks[k] || {}
                    return (c.fail || 0) > 0
                })
                names.sort()
                var mapName = function(k) {
                    var m = {
                        dns_ns: "dig",
                        whois: "whois",
                        ip2asn: "iptoasn",
                        ipthc: "ip.thc",
                        umbrella: "umbrella",
                        tor_nodes: "tor",
                        active_ssl: "tls"
                    }
                    return m[k] || k
                }
                return names.map(mapName).join(", ")
            } catch (e) {
                return ""
            }
        },
        grouped_alerts: function() {
            var groups = {}
            var levels = ['high', 'moderate', 'low']
            for (var li = 0; li < levels.length; li++) {
                var level = levels[li]
                var arr = (this.alerts && this.alerts[level]) ? this.alerts[level] : []
                for (var i = 0; i < arr.length; i++) {
                    var a = arr[i] || {}
                    var host = a.host || a.title || '—'
                    if (!groups[host]) {
                        groups[host] = {
                            host: host,
                            counts: { high: 0, moderate: 0, low: 0 },
                            alerts: { high: [], moderate: [], low: [] },
                            _services: {}
                        }
                    }
                    groups[host].counts[level] += 1
                    groups[host].alerts[level].push(a)
                    try {
                        var p = a.port
                        var proto = a.proto || a.protocol
                        if (p != null && proto) {
                            proto = String(proto).trim()
                            var portNum = parseInt(p, 10)
                            if (!isNaN(portNum) && portNum > 0 && proto) {
                                var s = `${portNum}/${proto.toUpperCase()}`
                                groups[host]._services[s] = true
                            }
                        }
                    } catch (e) {}
                }
            }
            return Object.keys(groups).map(function (k) {
                var g = groups[k]
                try {
                    var services = Object.keys(g._services || {})
                    services.sort()
                    g.service_summary = services.join(", ")
                    delete g._services
                } catch (e) {
                    g.service_summary = ""
                }
                return g
            })
        }
    },
    props: {
        capture_token: String
    },
    methods: {
        load_report: function() {
            if (!this.capture_token) return;
            axios.get(`/api/analysis/report/${this.capture_token}`, { timeout: 60000 })
                .then(response => {
                    if (response.data && response.data.message !== 'No report yet') {
                        this.device = response.data.device
                        this.methods = response.data.methods
                        this.pcap = response.data.pcap
                        this.records = response.data.records || []
                        this.analysis_meta = response.data.analysis_meta || null
                        var a = response.data.alerts || {}
                        this.alerts = {
                            high: Array.isArray(a.high) ? a.high : [],
                            moderate: Array.isArray(a.moderate) ? a.moderate : [],
                            low: Array.isArray(a.low) ? a.low : []
                        }
                        this.detection_methods = ""
                        this.uncategorized_records = []
                        this.whitelisted_records = []
                        if (this.methods) this.get_detection_methods();
                        if (this.records && this.records.length) this.get_records();
                    }
                })
                .catch(error => { console.log(error); });
        },
        save_capture: function() {
            console.log("[report.vue] Saving the capture");
            router.replace({ name: 'save-capture', params: { capture_token: this.capture_token } });
        },
        new_capture: function() {
            console.log("[report.vue] Deleting the capture and creating a new AP");
            axios.get('/api/misc/delete-captures', { timeout: 30000 })
            .then(() => { router.push({ name: 'generate-ap' }) })
            .catch(error => { console.log(error) })
        },
        /** Spelled number for alert count; avoids i18n / index crashes on the summary screen. */
        alertCountWord: function(level) {
            try {
                var arr = this.alerts && this.alerts[level]
                var n = Array.isArray(arr) ? arr.length : 0
                var loc = this.$i18n && this.$i18n.locale
                var nums = loc && this.$i18n.messages[loc] && this.$i18n.messages[loc].report && this.$i18n.messages[loc].report.numbers
                if (nums && n >= 0 && n < nums.length) return nums[n]
                return String(n)
            } catch (e) {
                return "0"
            }
        },
        grep_keyword: function(kw, level){
            try {
                var arr = this.alerts && this.alerts[level]
                if (!Array.isArray(arr) || !arr.length) return false
                var found = false
                arr.forEach((a) => {
                    if (a && a.title && a.title.indexOf(kw) > 0) found = true
                })
                return found
            } catch (error) {
                console.log(error)
                return false
            }
        },
        /** Avoid render crash when capinfos is missing or incomplete. */
        pcapField: function(key) {
            if (!this.pcap || this.pcap[key] == null) return "—"
            return this.pcap[key]
        },
        pcapTimeFirst: function(key) {
            if (!this.pcap || this.pcap[key] == null) return "—"
            var s = String(this.pcap[key])
            var i = s.indexOf(",")
            return i >= 0 ? s.slice(0, i) : s
        },
        get_detection_methods: function(){
            var m = this.methods || {}
            this.detection_methods += (m.iocs == true)? `☑ ${this.$t("report.indicators")} ` : `☐ ${this.$t("report.indicators")} `
            this.detection_methods += (m.heuristics == true)? `☑ ${this.$t("report.heuristics")} ` : `☐ ${this.$t("report.heuristics")} `
            this.detection_methods += (m.active == true)? `☑ ${this.$t("report.active")} ` : `☐ ${this.$t("report.active")} `
        },
        add_whitelist: function(host){
            bus.emit("showModal", {"action" : "whitelist", "host" : host})
        },
        isIpAddress: function(value) {
            if (!value) return false
            var s = String(value).trim()
            // ipv4
            if (/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(s)) {
                var parts = s.split('.')
                for (var i = 0; i < parts.length; i++) {
                    var n = parseInt(parts[i], 10)
                    if (isNaN(n) || n < 0 || n > 255) return false
                }
                return true
            }
            // ipv6 (simple heuristic)
            if (s.indexOf(':') !== -1 && /^[0-9a-fA-F:]+$/.test(s)) return true
            return false
        },
        hostTitlePrefix: function(host) {
            try {
                return this.isIpAddress(host) ? this.$t("report.ip_address_prefix") : this.$t("report.host_prefix")
            } catch (e) {
                return ""
            }
        },
        alertKey: function(alert) {
            try {
                return [alert.id, alert.level, alert.host, alert.title].filter(Boolean).join('|')
            } catch (e) {
                return String(Math.random())
            }
        },
        /** ICMP / ICMPv6: no meaningful TCP/UDP destination port — omit in the port column. */
        isIcmpLikeProtocol: function(name) {
            var u = (name || '').toUpperCase()
            if (!u) return false
            if (u === 'ICMP' || u === 'IPV6-ICMP' || u === 'ICMPV6' || u === 'ICMP6') return true
            return u.indexOf('ICMP') !== -1
        },
        protocolsAsList: function(record) {
            var protos = record && record.protocols
            if (protos == null) return []
            return Array.isArray(protos) ? protos : Object.keys(protos).map(function (k) { return protos[k] })
        },
        formatProtocolNames: function(record) {
            return this.protocolsAsList(record).map(function (p) { return (p && p.name) ? p.name : "—" }).join(", ")
        },
        formatRecordPorts: function(record) {
            var list = this.protocolsAsList(record)
            var parts = []
            for (var i = 0; i < list.length; i++) {
                var p = list[i]
                if (!p) continue
                if (this.isIcmpLikeProtocol(p.name)) continue
                var port = p.port
                var pn = typeof port === 'number' ? port : parseInt(port, 10)
                var missing = port === undefined || port === null || port === '' || port === '-' || port === '--'
                var isNegOne = port === -1 || port === '-1' || (!isNaN(pn) && pn < 0)
                if (missing || isNegOne)
                    parts.push('--')
                else
                    parts.push(String(port))
            }
            return parts.join(', ')
        },
        formatDomainsWithUmbrellaRank: function(record) {
            var doms = (record && record.domains) ? record.domains : []
            if (!Array.isArray(doms) || !doms.length) return "—"
            var ranks = record && record.domains_umbrella_rank ? record.domains_umbrella_rank : {}
            return doms.map(function (d) {
                var r = ranks && (ranks[d] != null ? ranks[d] : ranks[String(d)])
                return r ? `${d} (${r})` : d
            }).join(", ")
        },
        formatDomainsWithUmbrellaRankParts: function(record) {
            var doms = (record && record.domains) ? record.domains : []
            if (!Array.isArray(doms) || !doms.length) return [{ text: "—", cls: "" }]
            var ranks = record && record.domains_umbrella_rank ? record.domains_umbrella_rank : {}
            var out = []
            for (var i = 0; i < doms.length; i++) {
                var d = doms[i]
                if (i > 0) out.push({ text: ", ", cls: "" })
                var r = ranks && (ranks[d] != null ? ranks[d] : ranks[String(d)])
                if (r) {
                    out.push({ text: String(d), cls: "" })
                    out.push({ text: ` (${r})`, cls: "muted-rank" })
                } else {
                    out.push({ text: String(d), cls: "" })
                }
            }
            return out
        },
        formatIpShort: function(value) {
            if (!value) return "—"
            var s = String(value).trim()
            // IPv4
            if (s.indexOf('.') !== -1) return s
            // Not IPv6 literal
            if (s.indexOf(':') === -1) return s
            try {
                // Remove zone id (fe80::1%wlan0)
                var zoneIdx = s.indexOf('%')
                if (zoneIdx >= 0) s = s.slice(0, zoneIdx)
                s = s.toLowerCase()
                // Expand '::'
                var sides = s.split('::')
                if (sides.length > 2) return s
                var left = sides[0] ? sides[0].split(':').filter(Boolean) : []
                var right = sides.length === 2 && sides[1] ? sides[1].split(':').filter(Boolean) : []
                // Handle embedded IPv4 in tail (not expected here, but keep safe)
                if (right.length && right[right.length - 1].indexOf('.') !== -1) return s
                var total = left.length + right.length
                var missing = sides.length === 2 ? Math.max(0, 8 - total) : 0
                var parts = []
                for (var i = 0; i < left.length; i++) parts.push(left[i])
                for (var i = 0; i < missing; i++) parts.push('0')
                for (var i = 0; i < right.length; i++) parts.push(right[i])
                if (parts.length !== 8) return s
                // Normalize: strip leading zeros per hextet
                for (var i = 0; i < parts.length; i++) {
                    var p = parts[i]
                    if (!p) p = '0'
                    p = p.replace(/^0+/, '')
                    parts[i] = p ? p : '0'
                }
                // Find longest run of zeros for compression
                var bestStart = -1, bestLen = 0
                var curStart = -1, curLen = 0
                for (var i = 0; i < parts.length; i++) {
                    if (parts[i] === '0') {
                        if (curStart === -1) curStart = i
                        curLen++
                    } else {
                        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
                        curStart = -1; curLen = 0
                    }
                }
                if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
                // Compress only if run length >= 2
                if (bestLen >= 2) {
                    var head = parts.slice(0, bestStart).join(':')
                    var tail = parts.slice(bestStart + bestLen).join(':')
                    if (!head && !tail) return '::'
                    if (!head) return '::' + tail
                    if (!tail) return head + '::'
                    return head + '::' + tail
                }
                return parts.join(':')
            } catch (e) {
                return String(value)
            }
        },
        get_records: function(){
            this.records.forEach( r => {
                if (!r.suspicious && !r.whitelisted){
                    this.uncategorized_records.push(r);
                } else if (r.whitelisted){
                    this.whitelisted_records.push(r);
                }
            })
        }
    },
    created: function() {
        console.log("[report.vue] Showing report.vue");
        this.load_report();
    }
}
</script>
