const Secret = {
    props: ['session'],
    components: {
        'secret-create-modal': SecretCreateModal,
        'secret-update-modal': SecretUpdateModal,
        'secret-table': SecretTable,
        'secret-delete-confirm-modal': SecretDeleteConfirmModal,
        'secret-hide-confirm-modal': SecretHideConfirmModal,
    },
    data() {
        return {
            selectedSecret: {
                name: null,
            },
            loadingDelete: false,
            loadingHide: false,
            isInitDataFetched: false,
            showConfirmDelete: false,
            showConfirmHide: false,
        }
    },
    mounted() {
        this.$nextTick(function () {
            this.isInitDataFetched = true;
          })
    },
    methods: {
        refreshSecretTable() {
            $("#secret-table").bootstrapTable('refresh');
            $('#secret-table').off('click', 'tbody tr:not(.no-records-found)')
        },
        hideSecret() {
            this.loadingHide = true;
            const api_url = this.$root.build_api_url('secrets', 'hide', {api_version: 0})
            fetch(`${api_url}/${getSelectedProjectId()}/${this.selectedSecret.name}`, {
                method: 'POST'
            }).then((data) => {
                this.refreshSecretTable();
            }).finally(() => {
                this.loadingHide = false;
                this.showConfirmHide = !this.showConfirmHide;
                showNotify('SUCCESS', 'Secret is hidden');
            })
        },
        switcherDeletingSecret() {
            this.secretDeletingType === 'single' ? this.deleteSecret() : this.deleteSelectedSecrets();
        },
        deleteSecret() {
            this.loadingDelete = true;
            const api_url = this.$root.build_api_url('secrets', 'secret', {api_version: 0})
            fetch(`${api_url}/${getSelectedProjectId()}/${this.selectedSecret.name}`, {
                method: 'DELETE',
            }).then((data) => {
                this.refreshSecretTable();
            }).finally(() => {
                this.loadingDelete = false;
                this.showConfirmDelete = !this.showConfirmDelete;
                showNotify('SUCCESS', 'Secret is deleted');
            })
        },
        deleteSelectedSecrets() {
            const selectedSecretList = $("#secret-table").bootstrapTable('getSelections')
                .map(secret => secret.name.toLowerCase());
            this.loadingDelete = true;
            const api_url = this.$root.build_api_url('secrets', 'delete', {api_version: 0})
            fetch(`${api_url}/${getSelectedProjectId()}/`,{
                method: 'POST',
                headers: {'Content-Type': 'application/json', dataType: 'json'},
                body: JSON.stringify({'secrets': selectedSecretList})
            }).then((response) => {
                if (response.ok) {
                    this.refreshSecretTable();
                    this.loadingDelete = false;
                    this.showConfirmDelete = !this.showConfirmDelete;
                    showNotify('SUCCESS', 'Secrets are deleted');
                } else if (response.status === 400){
                    showNotify('ERROR', 'Error in deleting secrets');
                }
            })
        },
        openConfirmHide(secret='') {
            this.showConfirmHide = !this.showConfirmHide;
            this.selectedSecret.name = secret;
        },
        openConfirmDelete(type, secret='') {
            this.secretDeletingType = type;
            this.showConfirmDelete = !this.showConfirmDelete;
            this.selectedSecret.name = secret;
        },
        openUpdateModal(secret='') {
            this.selectedSecret.name = secret;
            $('#secretUpdateModal').modal('show');
        }
    },
    template: ` 
        <main class="p-3">
            <secret-table
                @open-confirm-delete="openConfirmDelete"
                :is-init-data-fetched="isInitDataFetched">
            </secret-table>
            <secret-create-modal
                @refresh-table="refreshSecretTable">
            </secret-create-modal>
            <secret-update-modal
                :selected-secret="selectedSecret"
                @refresh-table="refreshSecretTable">>
            </secret-update-modal>
            <secret-delete-confirm-modal
                v-if="showConfirmDelete"
                @close-confirm="openConfirmDelete"
                :loading-delete="loadingDelete"
                @delete-secret="switcherDeletingSecret">
            </secret-delete-confirm-modal>
            <secret-hide-confirm-modal
                v-if="showConfirmHide"
                @close-confirm="openConfirmHide"
                :loading-hide="loadingHide"
                @hide-secret="hideSecret">
            </secret-hide-confirm-modal>
        </main>
    `
};

register_component('secret', Secret);
