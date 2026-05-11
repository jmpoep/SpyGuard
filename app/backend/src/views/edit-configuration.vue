<template>
    <div class="backend-content" id="content">
        <div v-bind:class="{ 'alert-toaster-visible' : toaster.show, 'alert-toaster-hidden' : !toaster.show }">{{toaster.message}}</div>
        <div class="column col-8 col-xs-12">
            <h3 class="s-title">Configuration</h3>
            <div class="form-group">
                <label class="form-label" for="device-id">Device UUID (read-only)</label>
                <div class="input-group">
                    <input class="form-input read-only" id="device-id" v-model="config.device_uuid" readonly="readonly">
                </div>
            </div>
            <div class="form-group">
                <label class="form-label" for="spyguard-server">SpyGuard server</label>
                <div class="input-group">
                    <input class="form-input" id="spyguard-server" type="text" autocomplete="url" v-model="config.frontend.spyguard_server" placeholder="http://localhost:5000">
                    <button class="btn btn-primary input-group-btn px150" type="button" @click="change_spyguard_server()">Update</button>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label" for="ui-zoom">UI zoom</label>
                <div class="input-group">
                    <select class="form-select" id="ui-zoom" v-model.number="config.frontend.ui_zoom">
                        <option v-for="z in [100,110,120,130,140,150]" :key="z" :value="z">{{ z }}%</option>
                    </select>
                    <button class="btn btn-primary input-group-btn px150" type="button" @click="change_ui_zoom()">Update</button>
                </div>
            </div>
            <h5 class="s-subtitle">Device configuration</h5>
            <div class="form-group">
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'virtual_keyboard')" v-model="config.frontend.virtual_keyboard">
                    <i class="form-icon"></i> Use virtual keyboard (for touch screen)
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'shutdown_option')" v-model="config.frontend.shutdown_option">
                    <i class="form-icon"></i> Allow the end-user to shutdown the device.
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'backend_option')" v-model="config.frontend.backend_option">
                    <i class="form-icon"></i> Allow the end-user to access to the backend.
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('network', 'tokenized_ssids')" v-model="config.network.tokenized_ssids">
                    <i class="form-icon"></i> Use tokenized SSIDs (eg. [ssid-name]-[hex-str]).
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'sparklines')" v-model="config.frontend.sparklines">
                    <i class="form-icon"></i> Show background sparklines during the capture.
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'slideshow')" v-model="config.frontend.slideshow">
                    <i class="form-icon"></i> Show tips for actions to perform during the capture.
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('frontend', 'remote_access')" v-model="config.frontend.remote_access">
                    <i class="form-icon"></i> Allow remote access to the frontend.
                </label>
                <label class="form-switch">
                    <input type="checkbox" @change="switch_config('backend', 'remote_access')" v-model="config.backend.remote_access">
                    <i class="form-icon"></i> Allow remote access to the backend.
                </label>
                <h5 class="s-subtitle">Capture export</h5>
                <div class="form-group">
                    <label class="form-switch">
                        <input type="checkbox" :checked="config.frontend.capture_export === 'server'" @change="on_capture_export_change('server', $event)">
                        <i class="form-icon"></i> Send encrypted capture to the SpyGuard server (third-party sharing)
                    </label>
                    <label class="form-switch">
                        <input type="checkbox" :checked="config.frontend.capture_export === 'usb'" @change="on_capture_export_change('usb', $event)">
                        <i class="form-icon"></i> Save on USB key
                    </label>
                    <label class="form-switch">
                        <input type="checkbox" :checked="config.frontend.capture_export === 'browser'" @change="on_capture_export_change('browser', $event)">
                        <i class="form-icon"></i> Download in the browser
                    </label>
                </div>
                
            </div>
            <h5 class="s-subtitle">User credentials</h5>
            <div class="form-group">
                <div class="column col-10 col-xs-12">
                    <div class="form-group">
                        <label class="form-label" for="user-login">User login</label>
                        <div class="input-group">
                            <input class="form-input" id="user-login" type="text" v-model="config.backend.login">
                            <button class="btn btn-primary input-group-btn px150" @click="change_login()">Update it</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="user-login">User password</label>
                        <div class="input-group">
                            <input class="form-input" id="user-login" type="password" placeholder="●●●●●●" v-model="config.backend.password">
                            <button class="btn btn-primary input-group-btn px150" @click="change_password()">Update it</button>
                        </div>
                    </div>
                    <div class="whitespace"></div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'

export default {
    name: 'edit-configuration',
    data() {
        return {
            config: {},
            check_certificate: false,
            certificate: "",
            iocs_tags: [],
            toaster: { show: false, message : "", type : null }
        }
    },
    props: {},
    methods: {
        on_capture_export_change: function(value, evt) {
            if (evt.target.checked) {
                this.config.frontend.capture_export = value
                this.save_capture_export()
            } else if (this.config.frontend.capture_export === value) {
                evt.target.checked = true
            }
        },
        save_capture_export: function() {
            var v = this.config.frontend.capture_export
            if (!v || !['usb', 'browser', 'server'].includes(v)) return
            axios.get(`/api/config/edit/frontend/capture_export/${v}`, {
                timeout: 10000,
                headers: { 'X-Token': this.jwt }
            }).then(response => {
                if (response.data.status) {
                    this.toaster = { show: true, message: 'Configuration updated', type: 'success' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 1000)
                } else {
                    this.toaster = { show: true, message: response.data.message || 'Update failed', type: 'error' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 2000)
                }
            }).catch(err => console.log(err))
        },
        switch_config: function(cat, key) {
            axios.get(`/api/config/switch/${cat}/${key}`, {
                    timeout: 10000,
                    headers: { 'X-Token': this.jwt }
                }).then(response => {
                    if (response.data.status) {
                        if (response.data.message == "Key switched to true") {
                            this.toaster = { show : true, message : "Configuration updated", type : "success" }
                            setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                            this.config[cat][key] = true
                        } else if (response.data.message == "Key switched to false") {
                            this.toaster = { show : true, message : "Configuration updated", type : "success" }
                            setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                            this.config[cat][key] = false
                        } else {
                            this.toaster = { show : true, message : "The key doesn't exist", type : "error" }
                            setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                        }
                    }
                })
                .catch(err => (console.log(err)))
        },
        load_config: function() {
            axios.get(`/api/config/list`, {
                    timeout: 10000,
                    headers: { 'X-Token': this.jwt }
                }).then(response => {
                    if (response.data) {
                        this.config = response.data
                        this.config.backend.password = ""
                    }
                })
                .catch(err => (console.log(err)))
        },
        async get_jwt() {
            await axios.get(`/api/get-token`, { timeout: 10000 })
                .then(response => {
                    if (response.data.token) {
                        this.jwt = response.data.token
                    }
                })
                .catch(err => (console.log(err)))
        },
        change_spyguard_server: function() {
            var u = (this.config.frontend && this.config.frontend.spyguard_server) ? String(this.config.frontend.spyguard_server).trim() : ''
            if (!u) {
                this.toaster = { show: true, message: 'SpyGuard server URL cannot be empty', type: 'error' }
                setTimeout(function () { this.toaster = { show: false } }.bind(this), 2000)
                return
            }
            axios.get(`/api/config/edit/frontend/spyguard_server/${encodeURIComponent(u)}`, {
                timeout: 10000,
                headers: { 'X-Token': this.jwt }
            }).then(response => {
                if (response.data.status) {
                    this.config.frontend.spyguard_server = u.replace(/\/+$/, '')
                    this.toaster = { show: true, message: 'SpyGuard server updated', type: 'success' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 1000)
                } else {
                    this.toaster = { show: true, message: response.data.message || 'Update failed', type: 'error' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 2000)
                }
            }).catch(err => console.log(err))
        },
        change_ui_zoom: function() {
            var z = (this.config.frontend && this.config.frontend.ui_zoom != null) ? Number(this.config.frontend.ui_zoom) : 100
            if (!Number.isFinite(z)) z = 100
            z = Math.round(z / 10) * 10
            if (z < 100) z = 100
            if (z > 150) z = 150
            axios.get(`/api/config/edit/frontend/ui_zoom/${z}`, {
                timeout: 10000,
                headers: { 'X-Token': this.jwt }
            }).then(response => {
                if (response.data.status) {
                    this.config.frontend.ui_zoom = z
                    this.toaster = { show: true, message: 'UI zoom updated', type: 'success' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 1000)
                } else {
                    this.toaster = { show: true, message: response.data.message || 'Update failed', type: 'error' }
                    setTimeout(function () { this.toaster = { show: false } }.bind(this), 2000)
                }
            }).catch(err => console.log(err))
        },
        change_login: function() {
            axios.get(`/api/config/edit/backend/login/${this.config.backend.login}`, {
                    timeout: 10000,
                    headers: { 'X-Token': this.jwt }
            }).then(response => {
                if (response.data.status) {
                    this.toaster = { show : true, message : "Login changed", type : "success" }
                    setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                } else {
                    this.toaster = { show : true, message : "Login not changed", type : "error" }
                    setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                }
            })
            .catch(err => (console.log(err)))
        },
        change_password: function() {
            axios.get(`/api/config/edit/backend/password/${this.config.backend.password}`, {
                    timeout: 10000,
                    headers: { 'X-Token': this.jwt }
                }).then(response => {
                    if (response.data.status) {
                        this.toaster = { show : true, message : "Password changed", type : "success" }
                        setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                    } else {
                        this.toaster = { show : true, message : "Password not changed", type : "error" }
                        setTimeout(function () { this.toaster = { show : false } }.bind(this), 1000)
                    }
                })
                .catch(err => (console.log(err)))
        }
    },
    created: function() {
        this.get_jwt().then(() => {
            this.load_config();
        });
    }
}
</script>
