<template>
    <div v-if="display">
        <div class="blurred-wrapper" v-on:click="hide_modal()"></div>
        <div class="modal-window" v-if="display_shudown">
            <div class="modal-content">
                <p>{{ $t("modals.want_to_quit") }}</p>
                <button class="btn btn-primary" v-on:click="hide_modal()">{{ $t("modals.no_go_back") }}</button> <button class="btn btn-primary" v-on:click="shutdown()">{{ $t("modals.yes_continue") }}</button>
            </div>
        </div>
        <div class="modal-window" v-if="display_whitelist">
            <div class="modal-content">
                <p v-if="whitelist_success" v-html="$t('modals.whitelist_success', { host: host || '—' })"></p>
                <p v-else v-html="$t('modals.want_to_whitelist', { host: host || '—' })"></p>
                <button class="btn btn-primary" v-if="!whitelist_success" v-on:click="hide_modal()">{{ $t("modals.no_go_back") }}</button>
                <button class="btn btn-primary" style="margin-left:10px" v-if="!whitelist_success" v-on:click="add_whitelist()">{{ $t("modals.yes_continue") }}</button>
            </div>
        </div>
        <div class="modal-window" v-if="display_wifi">
            <div class="modal-content">
                <p>{{ $t("modals.please_give_the_password") }} <strong>{{ wifi_network }}</strong> </p>
                
                <div class="form-group">
                    <div @click="show_password" :class="password_class"></div>
                    <input :type="type" class="form-input" id="password" v-model="password" :placeholder="$t('wifi-select.wifi_password')" v-on:click="show_keyboard = true;">
                </div>
                <div class="form-group">
                    <button class="btn width-100" :class="[ wifi_connecting ? 'loading' : '', wifi_success ? 'btn-success' : 'btn-primary', ]" v-on:click="wifi_setup()">{{ btn_wifi_val }}</button>
                </div>
            </div>
        </div>
        <div class="keyboard_wrapper" v-if="show_keyboard">
            <SimpleKeyboard @onChange="onChange" @onKeyPress="onKeyPress" :input="input" />
        </div>
    </div>
</template>

<script>
import axios from 'axios'
import router from '../router'
import SimpleKeyboard from "./SimpleKeyboard.vue";
import { bus } from "@/bus"

export default {
    name: 'Modals',
    data: function (){
        return {
            btn_wifi_val: this.$t("wifi-select.connect_to_it"),
            wifi_connecting: false,
            error: false,
            wifi_success: false,
            password: "",
            host: "",
            whitelist_success: false,
            capture_token: "",
            display_whitelist: false,
            display_shudown: false,
            display_wifi: false,
            display: false,
            wifi_network: "",
            show_keyboard: false,
            input: "",
            type:"password",
            password_class:"password-show"
        }
    },
    components: {
        SimpleKeyboard
    },
    methods: {
        hide_modal: function(){
            this.display = false;
        },
        shutdown: function(){
            axios.get(`/api/misc/shutdown`, { timeout: 30000 })
        },
        add_whitelist: function(){
            axios.get(`/api/misc/whitelist/${this.host}`, { timeout: 30000 })
            .then((response) => {
                if (response && response.data && response.data.status === true) {
                    // Prefer the normalized element returned by API if present.
                    if (response.data.element) this.host = String(response.data.element)
                    this.whitelist_success = true
                    setTimeout(() => { this.display = false }, 2000)
                }
            })
            .catch((err) => { console.log(err) })
        },
        onChange(input) {
            this.input = input
            this.password = this.input;
        },
        onKeyPress(button) {
            if (button == "{enter}") this.show_keyboard = false
        },
        onInputChange(input) {
            this.input = input.target.value;
        },
        show_password() {
            if(this.type === 'password') {
                this.type = 'text'
                this.password_class = "password-hide"
            } else {
                this.type = 'password'
                this.password_class = "password-show"
            }
        },
        wifi_setup: function() {
            if (this.password.length >= 8 ){
                this.wifi_connecting = true
                axios.post('/api/network/wifi/setup', { ssid: this.wifi_network, password: this.password }, { timeout: 60000 })
                .then(response => {
                    if(response.data.status) {
                        this.wifi_success = true
                        this.wifi_connecting = false
                        this.btn_wifi_val = this.$t('wifi-select.wifi_connected')
                        setTimeout(() => {
                            this.display = false
                            this.btn_wifi_val = this.$t("wifi-select.connect_to_it")
                            router.push({ name: 'generate-ap' }); 
                        }, 1000);
                    } else {
                        this.btn_wifi_val = this.$t('wifi-select.wifi_not_connected')
                        this.wifi_connecting = false
                        setTimeout(() => {
                            this.btn_wifi_val = this.$t("wifi-select.connect_to_it")
                        }, 1000);
                    }
                });
            }
        }
    },
    created: function() {
        bus.on("showModal", args => {
            this.input = ""
            if(args.action == "shutdown"){
                this.show_keyboard = false
                this.display_wifi = false
                this.display_shudown = true
                this.display_whitelist = false
                this.display = true
            } else if(args.action == "wifi"){
                this.wifi_connecting = false
                this.wifi_success = false
                this.password = ""
                this.btnval = this.$t("wifi-select.connect_to_it");
                this.display_shudown = false
                this.display_wifi = true
                this.display_whitelist = false
                this.wifi_network = args.network_name
                this.display = true
            } else if(args.action == "whitelist"){
                this.show_keyboard = false
                this.display_wifi = false
                this.display_shudown = false
                this.display_whitelist = true
                this.host = (args && args.host != null) ? String(args.host).trim() : ""
                this.whitelist_success = false
                this.display = true
            }
        });
    }
}
</script>
