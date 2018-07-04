var site = {
    addCloseButtonEvents: function() {
        $("body").on("click", "button[data-close]", function(event) {
            $(event.target)
                .parents('[data-closable]')
                .first()
                .fadeOut(function () { $(this).remove(); });
        });
    },

    addFormInputCleanup:  function() {
        $("body").on("change", "input[aria-invalid]",function(event) {
            $(event.target).removeClass("is-invalid-input");
            var id = event.target.id;
            $("#"+id + "Label").removeClass("is-invalid-label");
        });
    },

    init: function() {
        $(document).ready(function() {
            site.addCloseButtonEvents();
            site.addFormInputCleanup();
        });
    }
};
