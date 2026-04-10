const SecretUpdateModal = {
    props: ['selectedSecret'],
    data() {
        return {
            secretData: {
                name: '',
                value: '',
            },
            isLoading: false,
            isUnsecret: false,
        }
    },
    computed: {
        isValueEmpty(){
            return !this.secretData.value
        },
    },
    mounted() {
        const vm = this;
        $("#secretUpdateModal").on("show.bs.modal", e => {
            vm.secretData.name = this.selectedSecret.name;
        });
        $("#secretCreateModal").on("hidden.bs.modal", e => {
            this.isUnsecret=false
        });
    },
    methods: {
        saveSecret() {
            this.isLoading = true;
            const api_url = this.$root.build_api_url('secrets', 'secret', {api_version: 0})
            fetch(`${api_url}/${getSelectedProjectId()}/${this.secretData.name}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json', dataType: 'json'},
                body: JSON.stringify({
                    "secret": {
                        "old_name": this.selectedSecret.name,
                        "value": this.secretData.value,
                    }
                })
            }).then((response) => response.json())
            .then(data => {
                this.isLoading = false;
                this.secretData.name = '';
                this.secretData.value = '';
                $('#secretUpdateModal').modal('hide');
                this.$emit('refresh-table');
                showNotify('SUCCESS', 'Secret updated.');
            }).catch(err => {
                this.isLoading = false;
                showNotify('ERROR', err);
                console.log(err)
            })
        },
    },
    template: `
    <div class="modal modal-small fixed-left fade shadow-sm" tabindex="-1" role="dialog" id="secretUpdateModal">
    <div class="modal-dialog modal-dialog-aside" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <div class="row w-100">
                    <div class="col">
                        <h2>Update secret</h2>
                    </div>
                    <div class="col-xs d-flex">
                        <button type="button" class="btn btn-secondary mr-2" data-dismiss="modal" aria-label="Close">
                            Cancel
                        </button>
                        <button type="button" 
                            class="btn btn-basic d-flex align-items-center"
                            @click="saveSecret"
                            :disabled="isValueEmpty"
                        >Save<i v-if="isLoading" class="preview-loader__white ml-2"></i></button>
                    </div>
                </div>
            </div>
            <div class="modal-body">
                <div class="section">
                    <div class="row" id="secretFields">
                        <div class="custom-input mb-3 w-100">
                            <label for="SecretUpdateName" class="font-weight-bold font-h5 mb-1">Name</label>
                            <input
                                id="SecretUpdateName"
                                type="text"
                                v-model="secretData.name"
                                placeholder="Secret name" disabled>
                        </div>
                        <div class="custom-input mb-3 w-100">
                            <div class="d-flex">
                                <div>
                                    <label for="SecretUpdateValue" class="font-weight-bold font-h5 mb-1">Value</label>
                                </div>
                                <div class="ml-auto d-flex">
                                    <div class="mr-2 font-h6">
                                        Unmask
                                    </div>
                                    <div>
                                        <label class="custom-toggle">
                                            <input
                                                name="toggle-group"
                                                type="checkbox"
                                                v-model="isUnsecret"
                                                >
                                            <span class="custom-toggle_slider round"></span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <textarea class="form-control"  :class="{'password-mask': !isUnsecret}" v-model="secretData.value" rows="8" id="SecretUpdateValue"></textarea>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
    `
}
