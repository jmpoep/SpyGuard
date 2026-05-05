<template>
    <div class="wrapper">
        <svg id="sparkline" stroke-width="3" :width="sparkwidth" :height="sparkheight" v-if="sparklines"></svg>
        <div class="center">
            <div class="footer">
                <div class="timer-row">
                    <span class="rec-dot" aria-hidden="true"></span>
                    <h3 class="timer">{{timer_hours}}:{{timer_minutes}}:{{timer_seconds}}</h3>
                </div>
                <transition name="fade" mode="out-in">
                    <p v-if="slideshow" :key="messageKey" class="capture-rotating-msg" v-html="rotatingMessage"></p>
                </transition>
                <div class="empty-action">
                    <button class="btn btn-primary" v-on:click="stop_capture()">{{$t("capture.stop_btn")}}</button>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'
import router from '../router'
import sparkline from '@fnando/sparkline'

export default {
    name: 'capture',
    components: {},
    data() {
        return {
            timer_hours: "00",
            timer_minutes: "00",
            timer_seconds: "00",
            stats_interval: false,
            chrono_interval: false,
            message_interval: false,
            sparklines: false,
            /** Rotating capture tips; driven by config frontend.slideshow (default true). */
            slideshow: false,
            capture_start_ms: null,
            messageIndex: 0
        }
    },
    props: {
        capture_token: String,
        capture_start: [String, Number],
        device_name: String
    },
    computed: {
        rotatingMessage: function() {
            // Index 0: existing “interception…” message with device name.
            if (this.messageIndex === 0) {
                const deviceName = this.escapeHtml(this.device_name || "")
                return `${this.$t("capture.intercept_coms_msg")}${deviceName}.`
            }
            // Index 1: short intro before action tips.
            if (this.messageIndex === 1) {
                return this.$t("capture.tip_begin")
            }

            const tips = [
                this.$t("capture.tip_smartphone_events_1"),
                this.$t("capture.tip_smartphone_events_2"),
                this.$t("capture.tip_smartphone_events_3"),
                this.$t("capture.tip_smartphone_events_4"),
                this.$t("capture.tip_send_sms"),
                this.$t("capture.tip_check_mailbox"),
                this.$t("capture.tip_take_photo"),
                this.$t("capture.tip_move_phone"),
                this.$t("capture.tip_duration_ideal"),
                this.$t("capture.tip_coffee_tea")
            ]

            const i = (this.messageIndex - 2) % tips.length
            return tips[i]
        },
        messageKey: function() {
            // Ensures transition triggers when text changes.
            return `msg-${this.messageIndex}`
        }
    },
    methods: {
        escapeHtml: function(value) {
            return String(value)
                .replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll('"', "&quot;")
                .replaceAll("'", "&#39;")
        },
        start_rotating_messages: function() {
            // Start with interception message for 15 seconds, then rotate tips every 15 seconds.
            const intervalMs = 15 * 1000
            this.messageIndex = 0
            this.message_interval = setInterval(() => {
                this.messageIndex += 1
            }, intervalMs)
        },
        set_chrono: function() {
            console.log("[capture.vue] Setting up the chrono")
            // 1s resolution is enough for HH:MM:SS display.
            this.chrono_interval = setInterval(() => { this.chrono(); }, 1000);
        },
        stop_capture: function() {
            console.log("[capture.vue] Stoping the capture")
            // Optimistic UI: immediately switch to analysis view, while stopping capture in background.
            clearInterval(this.chrono_interval);
            clearInterval(this.stats_interval);
            window.access_point = ""
            var capture_token = this.capture_token
            router.replace({ name: 'analysis', params: { capture_token: capture_token } });

            axios.get('/api/capture/stop', { timeout: 30000 })
                .catch((err) => {
                    console.log(err)
                    // Fallback: try to stop the AP explicitly (best-effort).
                    return axios.get('/api/network/ap/stop', { timeout: 15000 }).catch((e) => console.log(e))
                })
        },
        get_stats: function() {
            console.log("[capture.vue] Getting capture statistics")
            axios.get('/api/capture/stats', { timeout: 30000 })
                .then(response => (this.handle_stats(response.data)))
        },
        handle_stats: function(data) {
            if (data.packets.length) sparkline(document.querySelector('#sparkline'), data.packets);
        },
        chrono: function() {
            if (!this.capture_start_ms) return
            var time = Date.now() - this.capture_start_ms
            this.timer_hours = Math.floor(time / (60 * 60 * 1000));
            this.timer_hours = (this.timer_hours < 10) ? '0' + this.timer_hours : this.timer_hours
            time = time % (60 * 60 * 1000);
            this.timer_minutes = Math.floor(time / (60 * 1000));
            this.timer_minutes = (this.timer_minutes < 10) ? '0' + this.timer_minutes : this.timer_minutes
            time = time % (60 * 1000);
            this.timer_seconds = Math.floor(time / 1000);
            this.timer_seconds = (this.timer_seconds < 10) ? '0' + this.timer_seconds : this.timer_seconds
        },
        apply_misc_config: function(data) {
            var d = data || {}
            this.slideshow = d.slideshow !== false
            if (d.sparklines) {
                console.log("[capture.vue] Setting up sparklines")
                this.sparklines = true
                this.sparkwidth = window.screen.width + 'px'
                this.sparkheight = Math.trunc(window.screen.height / 5) + 'px'
                this.stats_interval = setInterval(() => { this.get_stats(); }, 500)
            }
            if (this.slideshow) {
                this.start_rotating_messages()
            }
        },
        load_misc_config: function() {
            axios.get('/api/misc/config', { timeout: 60000 })
                .then(response => this.apply_misc_config(response.data))
                .catch((error) => {
                    console.log(error)
                    this.slideshow = true
                    this.start_rotating_messages()
                })
        }
    },
    created: function() {
        console.log("[capture.vue] Showing capture.vue")

        // Sparklines + slideshow (action tips); rotating messages only if slideshow is true.
        this.load_misc_config()

        // Start the chrono and get the first stats.
        this.capture_start_ms = this.capture_start ? Number(this.capture_start) : Date.now()
        // Ensure immediate render.
        this.chrono()
        this.set_chrono();
    },
    beforeUnmount: function() {
        if (this.chrono_interval) clearInterval(this.chrono_interval);
        if (this.stats_interval) clearInterval(this.stats_interval);
        if (this.message_interval) clearInterval(this.message_interval);
    }
}
</script>

<style scoped>
.timer-row {
    display: inline-flex;
    align-items: center;
    gap: 10px;
}

.rec-dot {
    display: inline-block;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: #e53d38;
    box-shadow: 0 0 0 0 rgba(229, 61, 56, 0.55);
    animation: recPulse 2s ease-in-out infinite;
    /* h3 baseline/line-box makes it look slightly low; nudge up */
    position: relative;
    top: -10px;
}

@keyframes recPulse {
    0% {
        filter: blur(0px);
        box-shadow: 0 0 0 0 rgba(229, 61, 56, 0.55);
        transform: scale(1);
        opacity: 1;
    }
    50% {
        filter: blur(0.6px);
        box-shadow: 0 0 0 10px rgba(229, 61, 56, 0.0);
        transform: scale(1.05);
        opacity: 0.95;
    }
    100% {
        filter: blur(0px);
        box-shadow: 0 0 0 0 rgba(229, 61, 56, 0.0);
        transform: scale(1);
        opacity: 1;
    }
}

.fade-enter-active,
.fade-leave-active {
    transition: opacity 450ms ease;
}
.fade-enter-from,
.fade-leave-to {
    opacity: 0;
}
</style>
