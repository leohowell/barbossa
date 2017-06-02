% rebase('base.tpl')

<div class="main-content">
<div class="row">
    <div class="col-md-12">
        %for group in groups:
        <div class="col-md-8">
            <div class="box border pink">
            <div class="box-title">
                <h4>
                    <img class="head-image" src="/contacts/avatar/{{ group['UserName'] }}">
                    【{{ group['NickName'] }}】 - {{ len(group['MemberList']) }}人
                </h4>
            </div>
            <div class="box-body">
                <table class="table table-bordered">
                    <thead>
                    <tr>
                        <th class="col-md-1">编号</th>
                        <th class="col-md-2">头像</th>
                        <th class="col-md-3">成员昵称</th>
                        <th class="col-md-3">成员群昵称</th>
                        <th class="col-md-1">user_id</th>
                        <th class="col-md-2">移除</th>
                    </tr>
                    </thead>
                    <tbody>
                    %for index, member in enumerate(group['MemberList'].values(), start=1):
                    <tr>
                        <td class="col-md-1">{{ index }}</td>
                        <td class="col-md-2"><img class="head-image" src="/contacts/avatar/{{ member['UserName'] }}"></td>
                        <td class="col-md-3">{{ member['NickName'] }}</td>
                        <td class="col-md-3">{{ member['DisplayName'] }}</td>
                        <td class="col-md-1">{{ member['UserName'] }}</td>
                        <td class="col-md-2">
                            <button class="btn btn-danger delete-member"
                                    data-url="/contacts/group/{{ group['UserName'] }}/{{ member['UserName'] }}">移除
                            </button>
                        </td>
                    </tr>
                    %end
                    </tbody>
                </table>
            </div>
        </div>
        </div>
        <div class="col-md-4">
            <div class="box border pink">
            <div class="box-title">
                <h4><img class="head-image" src="/contacts/avatar/{{ group['UserName'] }}"> 发送消息</h4>
            </div>
            <div class="box-body">
                <table class="table table-bordered table-striped">
                    <thead>
                    <tr>
                        <th>群消息(文本)</th>
                        <th>群图片(输入图片URL)</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td>
                            <form action="/message/text/{{ group['UserName'] }}" method="post">
                                <textarea name="message" class="form-control" rows="4"></textarea>
                                <input class="btn btn-success message-btn" type="submit" value="发送群消息" />
                            </form>
                        </td>
                        <td>
                            <form action="/message/image/{{ group['UserName'] }}" method="post">
                                <textarea name="url" class="form-control" rows="4"></textarea>
                            <input class="btn btn-success message-btn" type="submit" value="发送图片消息" />
                            </form>
                        </td>
                    </tr>
                    </tbody>
                </table>
            </div>
        </div>
        </div>
        %end
    </div>
</div>
</div>
<script>
    $(".delete-member").on("click", function (){
        $.ajax({
            url: $(this).data("url"),
            type: 'DELETE'
        }).done(function(data) {
            $(this).prop("disabled", true);
            $(this).text("已移除");
        });
    });
</script>
