var secretEvents = {
    actions(value, row, index) {
        return `
            <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-default btn-xs btn-table btn-icon__xs secret_view mr-2" 
                        data-toggle="tooltip" data-placement="top" title="View secret">
                    <i class="icon__18x18 icon-eye"></i>
                </button>
                <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-default btn-xs btn-table btn-icon__xs secret_copy mr-2" 
                        data-toggle="tooltip" data-placement="top" title="Copy secret">
                    <i class="icon__18x18 icon-copy"></i>
                </button>
                <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-default btn-xs btn-table btn-icon__xs secret_edit mr-2" 
                        data-toggle="tooltip" data-placement="top" title="Edit secret">
                    <i class="icon__18x18 icon-edit"></i>
                </button>
                <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-default btn-xs btn-table btn-icon__xs secret_hide mr-2" 
                        data-toggle="tooltip" data-placement="top" title="Hide secret">
                    <i class="icon__18x18 icon-lock"></i>
                </button>
                <div class="d-flex justify-content-end">
                <button type="button" class="btn btn-default btn-xs btn-table btn-icon__xs secret_delete" 
                        data-toggle="tooltip" data-placement="top" title="Delete secret">
                    <i class="icon__18x18 icon-delete"></i>
                </button>

            </div>
        `
    },
    name_style(value, row, index) {
        return {
            css: {
                "max-width": "140px",
                "overflow": "hidden",
                "text-overflow": "ellipsis",
                "white-space": "nowrap"
            }
        }
    },
    cell_style(value, row, index) {
        return {
            css: {
                "min-width": "165px"
            }
        }
    },
    cell_secret_style(value, row, index) {
        return {
            css: {
                "overflow": "hidden",
                "word-break": "break-all",
            }
        }
    },
    action_events: {
        "click .secret_edit": function (e, value, row, index) {
            // apiActions.run(row.id, row.name)
            console.debug('Edit the secret, row: ', row)
            e.stopPropagation();
            const vm = vueVm.registered_components.secret
            vm.openUpdateModal(row.name);
        },
        "click .secret_hide": function (e, value, row, index) {
            console.debug('Hide the secret, row: ', row)
            e.stopPropagation();
            const vm = vueVm.registered_components.secret
            vm.openConfirmHide(row.name);
        },
        "click .secret_delete": function (e, value, row, index) {
            console.debug('Delete the secret, row: ', row)
            e.stopPropagation();
            const vm = vueVm.registered_components.secret
            vm.openConfirmDelete('single', row.name);
        },
        "click .secret_view": async function (e, value, row, index) {
            console.debug('View the secret for row: ', row)
            e.stopPropagation();
            let _secret;
            if (row.secret === '******') {
                const api_url = V.build_api_url('secrets', 'secret', {api_version: 0})
                const resp = await fetch(`${api_url}/${getSelectedProjectId()}/${row.name}`)
                if (resp.ok) {
                    try {
                        const data = await resp.json()
                        _secret = data.secret
                    } catch (error) {
                        console.error('Error in receiving a secret: ', err);
                        showNotify('ERROR', 'Error in receiving a secret');
                        _secret = '******'
                    }
                }
            } else {
                _secret = '******'
            }
            $('#secret-table').bootstrapTable('updateRow', {
                index: index,
                row: {
                    secret: _secret,
                }
            })
        },
        "click .secret_copy": async function (e, value, row, index) {
            console.debug('Copy the secret template for row: ', row)
            e.stopPropagation();
            const secret_template = `{{${row.name}}}`
            try {
                /**
                * Copies the text to the system clipboard.
                * Clipboard is available only in secure contexts (HTTPS).
                * Check if using HTTPS and navigator.clipboard is available
                * Then uses standard clipboard API, otherwise uses fallback
                */
                if (window.isSecureContext && navigator.clipboard) {
                    await navigator.clipboard.writeText(secret_template);
                    console.debug('Text copied to clipboard [secure]');
                } else {
                    const textArea = document.createElement("textarea"); 
                    textArea.value=secret_template; 
                    document.body.appendChild(textArea); 
                    textArea.focus();textArea.select();
                    document.execCommand('copy')
                    document.body.removeChild(textArea)
                    console.debug('Text copied to clipboard [unsecure]');
                }
                showNotify('SUCCESS', 'Secret is copied');
            } catch (err) {
                showNotify('ERROR', 'Error in copying text');
                console.error('Error in copying text: ', err);
            }
        }
    }
}
