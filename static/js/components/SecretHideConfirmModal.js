const SecretHideConfirmModal = {
    props: ['loadingHide'],
    template: `
    <div class="modal-component">
        <div class="modal-card">
            <p class="font-bold font-h3 mb-4">Hide secret?</p>
            <p class="font-h4 mb-4">Are you sure to hide secret?</p>
            <div class="d-flex justify-content-end mt-4">
                <button type="button" class="btn btn-secondary mr-2" @click="$emit('close-confirm')">Cancel</button>
                <button
                    class="btn btn-basic mr-2 d-flex align-items-center"
                    @click="$emit('hide-secret')"
                >Hide<i v-if="loadingHide" class="preview-loader__white ml-2"></i></button>
            </div>
        </div>
    </div>
`
}
