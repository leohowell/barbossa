% rebase('base.tpl')

<div class="message-list">
    <pre class="message"></pre>
</div>

<script>
    var url = '/sse/message'
    var source = new EventSource(url);
    source.onopen = function (event) {
        $(".message").text("sse connected!");
    };
    source.onmessage = function (event) {
        var data = event.data;
        if (data === null) {
            // do nothing
        } else {
            // $(".message").text(data);
            $(".message-list").append("<pre>" + data +"</pre>")
        }
    };
    source.onerror = function (event) {
        $(".message").text("error happened!");
        source.close()
    };
</script>
