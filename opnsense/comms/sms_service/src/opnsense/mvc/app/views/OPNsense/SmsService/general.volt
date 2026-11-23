<script>
    $(document).ready(function() {
        mapDataToFormUI({'frm_general_settings': "/api/smsservice/general/get"}).done(function() {
            $('.selectpicker').selectpicker('refresh');
        });

        updateServiceControlUI('smsservice');

        $("#saveAct").click(function() {
            saveFormToEndpoint("/api/smsservice/general/set", 'frm_general_settings', function() {
                $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall("/api/smsservice/service/reconfigure", {}, function() {
                    updateServiceControlUI('smsservice');
                    $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general_settings']) }}
    <div class="col-md-12">
        <hr />
        <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i></button>
    </div>
</div>
