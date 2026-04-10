const SecretTable = {
    props: ['isInitDataFetched', ],
    data() {
        return {
            checkedSecretsList: [],
        }
    },
    computed: {
        isAnySecretSelected() {
            return this.checkedSecretsList.length > 0;
        },
        table_attributes() {
            const api_url = this.$root.build_api_url('secrets', 'secrets', {api_version: 0})
            return {
                'data-url': `${api_url}/${getSelectedProjectId()}`,
                'data-page-size': 10,
                'data-page-list': "[5, 10, 15]",
                id: 'secret-table',
                'data-side-pagination': 'client',
                'data-pagination-parts': ['pageInfoShort', 'pageSize', 'pageList']
            }
        }
    },
    watch: {
        isInitDataFetched() {
            this.setSecretEvents();
        }
    },
    methods: {
        setSecretEvents() {
            const vm = this;
            $('#secret-table').on('check.bs.table', (row, $element) => {
                this.checkedSecretsList.push($element.name);
            });
            $('#secret-table').on('uncheck.bs.table', (row, $element) => {
                this.checkedSecretsList = this.checkedSecretsList.filter(secret => {
                    return $element.name !== secret
                })
            });
            $('#secret-table').on('uncheck-all.bs.table', (row, $element) => {
                this.checkedSecretsList = [];
            });
            $('#secret-table').on('check-all.bs.table', (rowsAfter, rowsBefore) => {
                this.checkedSecretsList = rowsBefore.map(row => row.name);
            });
            $('#secret-table').on('post-body.bs.table', ($tableFooter) => {
                this.checkedSecretsList = [];
            });
        },
    },
    template: `
        <TableCard
            header='Secrets'
            :table_attributes="table_attributes"
            >
            <template #actions="{master}">
                <div class="d-flex justify-content-end">
                    <button type="button"
                        data-toggle="modal" 
                        data-target="#secretCreateModal"
                        class="btn btn-secondary btn-icon btn-icon__purple mr-2">
                        <i class="icon__14x14 icon-plus__big"></i>
                    </button>
                    <button type="button" 
                        @click="$emit('open-confirm-delete', 'multiple')"
                        :disabled="!isAnySecretSelected"
                        class="btn btn-secondary btn-icon btn-icon__purple mr-2">
                        <i class="icon__18x18 icon-delete"></i>
                    </button>
                </div>
            </template>
            <template #table_headers>
                <th scope="col" data-checkbox="true"></th>
                <th scope="col" data-sortable="true" style="width: 200px;" data-field="name">NAME</th>
                <th scope="col" data-sortable="true" 
                    data-cell-style="secretEvents.cell_secret_style"
                    data-field="secret" 
                    class="w-100">VALUE</th>
                <th scope="col" data-align="right" data-sortable="true"
                    data-cell-style="secretEvents.cell_style"
                    data-formatter=secretEvents.actions
                    data-events="secretEvents.action_events"
                >
                ACTIONS
                </th>        
            </template>
        </TableCard>
    `
}
