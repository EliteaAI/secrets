const CustomTextarea = {
    emits: ['valueChange'],
    data() {
        return {
            value: "",
        }
    },
    watch:{
        value(newValue, oldValue){
            console.log(newValue, oldValue)
            this.$emit('valueChange', newValue)
        },
    },
    methods: {
    },
    template: `
        <textarea 
            class="form-control" 
            style="font-family: text-security-disc;" 
            v-model="value" 
            rows="8"
        >    
        </textarea>
    `
};
register_component('custom-textarea', CustomTextarea);
