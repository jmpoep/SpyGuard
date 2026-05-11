<template>
    <div class="wrapper">
        <div class="center">
            <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" style="margin: auto; background: none; display: block; shape-rendering: auto;" width="194px" height="194px" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid">
                <circle cx="50" cy="50" r="0" fill="none" stroke="#dfdfdf" stroke-width="1">
                <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="0s"></animate>
                <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="0s"></animate>
                </circle><circle cx="50" cy="50" r="0" fill="none" stroke="#dadada" stroke-width="1">
                <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                </circle>
            </svg>
            <p class="legend" v-if="!long_waiting">{{ $t("analysis.please_wait_msg") }}</p>
            <p class="legend fade-in" v-if="long_waiting">{{ $t("analysis.some_time_msg") }}</p>
        </div>
    </div>
</template>

<script>
import router from '../router'
import axios from 'axios'

export default {
    name: 'analysis',   
    data() {
        return {
            check_alerts: false,
            long_waiting: false,
            long_waiting_timeout: null
        }
    },
    props: {
        capture_token: String
    },
    methods: {
        ensure_capture_stopped_then_start: function() {
            // The capture stop can take a few seconds (stop_monitoring, hotspot teardown, capinfos).
            // We switch to this view immediately for UX, then best-effort stop before starting analysis.
            axios.get('/api/capture/stop', { timeout: 45000 })
                .catch((err) => {
                    // It's ok if capture is already stopped / hotspot already deleted.
                    console.log(err)
                })
                .finally(() => {
                    // Small delay to let capinfos.json be written before analysis reads it.
                    setTimeout(() => this.start_analysis(), 300)
                })
        },
        start_analysis: function() {
            console.log("[analysis.vue] Starting the analysis...");
            this.long_waiting_timeout = setTimeout(function () { this.long_waiting = true }.bind(this), 15000);
            axios.get(`/api/analysis/start/${this.capture_token}`, { timeout: 60000 })
                .then(response => {
                    if(response.data.message == 'Analysis started')
                        this.check_alerts = setInterval(() => { this.get_alerts(); }, 500);
                })
                .catch(error => {
                    console.log(error);
                });
        },
        get_alerts: function() {
            axios.get(`/api/analysis/report/${this.capture_token}`, { timeout: 60000 })
                .then(response => {
                    if(response.data.message != 'No report yet'){
                        console.log("[analysis.vue] Got the results analysis, moving to report view");
                        clearInterval(this.check_alerts);
                        this.long_waiting = false
                        router.replace({
                            name: 'report',
                            params: { capture_token: this.capture_token }
                        });
                    } else {
                        console.log("[analysis.vue] No analysis results yet");
                    }
                })
                .catch(error => {
                    console.log(error);
                });
        },
    },
    created: function() {
        console.log("[analysis.vue] Showing analysis.vue");
        this.ensure_capture_stopped_then_start();
    },
    beforeUnmount: function() {
        if (this.check_alerts) clearInterval(this.check_alerts);
        if (this.long_waiting_timeout) clearTimeout(this.long_waiting_timeout);
    }
}
</script>
