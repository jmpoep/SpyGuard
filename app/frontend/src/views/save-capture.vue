<template>
    <div class="wrapper">
        <div class="center" v-if="viewState === 'checking_network'">
            <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" style="margin: auto; background: none; display: block; shape-rendering: auto;" width="194px" height="194px" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid">
                <circle cx="50" cy="50" r="0" fill="none" stroke="#dfdfdf" stroke-width="1">
                    <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="0s"></animate>
                    <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="0s"></animate>
                </circle>
                <circle cx="50" cy="50" r="0" fill="none" stroke="#dadada" stroke-width="1">
                    <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                    <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                </circle>
            </svg>
            <p class="legend">{{ $t("save-capture.checking_connection") }}</p>
        </div>
        <div class="center" v-else-if="viewState === 'cloud_upload'">
            <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" style="margin: auto; background: none; display: block; shape-rendering: auto;" width="194px" height="194px" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid">
                <circle cx="50" cy="50" r="0" fill="none" stroke="#dfdfdf" stroke-width="1">
                    <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="0s"></animate>
                    <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="0s"></animate>
                </circle>
                <circle cx="50" cy="50" r="0" fill="none" stroke="#dadada" stroke-width="1">
                    <animate attributeName="r" repeatCount="indefinite" dur="2.941176470588235s" values="0;43" keyTimes="0;1" keySplines="0 0.2 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                    <animate attributeName="opacity" repeatCount="indefinite" dur="2.941176470588235s" values="1;0" keyTimes="0;1" keySplines="0.2 0 0.8 1" calcMode="spline" begin="-1.4705882352941175s"></animate>
                </circle>
            </svg>
            <p class="legend">{{ $t("save-capture.uploading_report") }}</p>
        </div>
        <div class="center" v-else-if="viewState === 'cloud_done'">
            <div class="apcard-frame">
                <div class="card apcard report-cloud-card" v-on:click="new_capture()">
                <div class="columns">
                    <div class="column col-5 light-grey report-cloud-left">
                        <p class="report-cloud-left-text">
                            <template v-if="$te('save-capture.remote_download_hint_prefix') && $te('save-capture.remote_download_hint_suffix')">
                                {{ $t("save-capture.remote_download_hint_prefix") }}
                                <span class="report-cloud-site">SpyGuard.net</span>
                                {{ $t("save-capture.remote_download_hint_suffix") }}
                            </template>
                            <template v-else>
                                {{ $t("save-capture.remote_download_hint") }}
                            </template>
                        </p>
                    </div>
                    <div class="divider-vert white-bg" data-content="&gt;&gt;"></div>
                    <div class="column col-6">
                        <span class="light-grey">{{ $t("save-capture.capture_id") }}</span><br />
                        <h4 class="report-cloud-value">{{ cloud_capture_id }}</h4>
                        <span class="light-grey">{{ $t("save-capture.archive_password") }}</span><br />
                        <h4 class="report-cloud-value">{{ cloud_archive_password }}</h4>
                    </div>
                </div>
                </div>
            </div>
            <span class="legend">{{ $t("save-capture.tap_card_msg") }}</span>
        </div>
        <div class="center" v-else-if="viewState === 'cloud_error'">
            <p class="legend">{{ cloud_error_msg || $t("save-capture.upload_failed") }}</p>
            <div class="save-capture-error-actions">
                <button type="button" class="btn btn-primary" v-on:click="retryCloudUpload()">{{ $t("save-capture.retry_upload") }}</button>
                <button type="button" class="btn" v-on:click="fallbackToUsb()">{{ $t("save-capture.save_to_usb") }}</button>
            </div>
        </div>
        <div class="center" v-else-if="save_usb && init">
            <div class="canvas-anim" :class="{'anim-connect': !saved && !usb}" v-on:click="new_capture()">
                <div class="icon-spinner" v-if="!saved && usb"></div>
                <div class="icon-success" v-if="saved"></div>
                <div class="icon-usb"></div>
                <div class="icon-usb-plug"></div> 
            </div>
            <p class="legend" v-if="!saved && !usb"><br />{{ $t("save-capture.please_connect") }}</p>
            <p class="legend" v-if="!saved && usb"><br />{{ $t("save-capture.we_are_saving") }}</p>
            <p class="legend" v-if="saved"><br />{{ $t("save-capture.tap_msg") }}</p>
        </div>
        <div class="center" v-else-if="!save_usb && init">
            <div class="apcard-frame">
                <div class="card apcard export-browser-card">
                    <p class="legend">{{ $t("save-capture.capture_download") }}<br /><br /><br /></p>
                    <button class="btn btn-primary" v-on:click="new_capture()">{{ $t("save-capture.start_capture_btn") }}</button>
                    <iframe :src="download_url" class="frame-download"></iframe>
                </div>
            </div>
        </div>
    </div>
</template>

<style lang="scss">
    
    .canvas-anim {
    height: 120px;
    margin: 0 auto;
    position: relative;
    width: 205px;
    
    &.anim-connect {
        width: 300px;

        .icon-usb {
            -webkit-animation: slide-right 1s cubic-bezier(0.455, 0.030, 0.515, 0.955) infinite alternate both;
            animation: slide-right 1s cubic-bezier(0.455, 0.030, 0.515, 0.955) infinite alternate both;
        }
    }
}

.save-capture-error-actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    margin-top: 16px;
}
</style>

<script>
import axios from 'axios'
import router from '../router'

function exportMode() {
    var m = window.config && window.config.capture_export
    if (m === 'usb' || m === 'browser' || m === 'server') return m
    return 'server'
}

export default {
    name: 'save-capture',
    components: {},
    data() {
        return { 
            usb: false,
            saved: false,
            save_usb: false,
            init: false,
            viewState: null,
            cloud_capture_id: '',
            cloud_archive_password: '',
            cloud_error_msg: ''
        }
    },
    props: {
        capture_token: String
    },
    methods: {
        startUsbFlow: function() {
            if (this.interval) {
                clearInterval(this.interval)
                this.interval = null
            }
            this.init = true
            this.save_usb = true
            this.usb = false
            this.saved = false
            this.interval = setInterval(() => { this.check_usb() }, 500);
        },
        fallbackToUsb: function() {
            this.cloud_error_msg = ''
            this.viewState = null
            this.startUsbFlow()
        },
        startServerExportWithConnectivityCheck: function() {
            this.viewState = 'checking_network'
            axios.get('/api/network/status', { timeout: 15000 })
                .then(response => {
                    if (response.data && response.data.internet) {
                        this.startCloudUpload()
                    } else {
                        this.viewState = null
                        this.startUsbFlow()
                    }
                })
                .catch(() => {
                    this.startCloudUpload()
                })
        },
        startBrowserFlow: function() {
            this.init = true
            this.save_usb = false
            this.download_url = `/api/save/save-capture/${this.capture_token}/url`
        },
        check_usb: function() {
            console.log("[save-capture.vue] Checking connected USB device...");
            axios.get(`/api/save/usb-check`, { timeout: 30000 })
                .then(response => {
                    if(response.data.status) {
                        this.usb = true
                        clearInterval(this.interval)
                        this.save_capture()
                    }
                })
        },
        save_capture: function() {
            var capture_token = this.capture_token
            console.log("[save-capture.vue] Saving the capture on USB");
            axios.get(`/api/save/save-capture/${capture_token}/usb`, { timeout: 30000 })
                .then(response => {
                    if(response.data.status){
                        this.saved = true
                        console.log("[save-capture.vue] Capture saved, going back to main view");
                        this.timeout = setTimeout(() => router.push('/'), 60000);
                    } 
                })
        },
        applyCloudUploadError: function(data) {
            var d = data || {}
            var code = d.error || ''
            if (!code && d.message) {
                this.cloud_error_msg = d.message
                return
            }
            if (!code) {
                code = 'unknown'
            }
            var key = 'save-capture.upload_errors.' + code
            var params = {
                max_mb: d.max_mb != null ? d.max_mb : 300,
                http_status: d.http_status != null ? d.http_status : '',
                daily_limit: d.daily_limit != null ? d.daily_limit : 20,
                message: d.message || ''
            }
            if (this.$te(key)) {
                this.cloud_error_msg = this.$t(key, params)
            } else if (d.message) {
                this.cloud_error_msg = d.message
            } else {
                this.cloud_error_msg = this.$t('save-capture.upload_errors.unknown', params)
            }
        },
        startCloudUpload: function() {
            this.viewState = 'cloud_upload'
            axios.post(`/api/save/upload-cloud/${this.capture_token}`, {}, { timeout: 180000 })
                .then(response => {
                    if (response.data && response.data.status) {
                        this.cloud_capture_id = response.data.capture_id
                        this.cloud_archive_password = response.data.archive_password
                        this.viewState = 'cloud_done'
                    } else {
                        this.applyCloudUploadError(response.data)
                        this.viewState = 'cloud_error'
                    }
                })
                .catch(error => {
                    console.log(error)
                    var data = error.response && error.response.data
                    if (data) {
                        this.applyCloudUploadError(data)
                    } else {
                        this.applyCloudUploadError({
                            error: 'network',
                            message: (error.message || '').toString()
                        })
                    }
                    this.viewState = 'cloud_error'
                })
        },
        retryCloudUpload: function() {
            this.cloud_error_msg = ''
            this.startCloudUpload()
        },
        new_capture: function() {
            console.log("[save-capture.vue] Capture saved, generating a new access point");
            clearTimeout(this.timeout);
            if (this.interval) clearInterval(this.interval);
            router.push({ name: 'generate-ap' })
        }
    },
    created: function() {
        console.log("[save-capture.vue] Showing save-capture.vue");
        var mode = exportMode()
        if (mode === 'server') {
            this.startServerExportWithConnectivityCheck()
        } else if (mode === 'browser') {
            this.startBrowserFlow()
        } else {
            this.startUsbFlow()
        }
    },
    beforeUnmount: function() {
        if (this.interval) clearInterval(this.interval)
    }
}
</script>
