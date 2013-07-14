<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>用户管理中心--登录</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">
    <link href="/resource/bootstrap/css/bootstrap.css?v=1" rel="stylesheet"/>
    <link href="/resource/bootstrap/css/bootstrap-responsive.css?v=1" rel="stylesheet"/>
    <link href="/resource/admin/css/admin.css?v=1" rel="stylesheet"/>
    <!--[if lt IE 9]>
    <script src="/resource/js/html5shiv.js?v=1"></script>
    <![endif]-->

</head>
<body>
<div class="navbar navbar-inverse navbar-fixed-top">
    <div class="navbar-inner">
        <div class="container">
            <button type="button" class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>

            <a class="brand" href="#">
                后台管理系统 <sup>2.0</sup>
            </a>

            <div class="nav-collapse collapse">
                <ul class="nav pull-right">
                    <li class="">
                        <a href="#" class="">创建账户</a>
                    </li>
                    <li class="">
                        <a href="#" class="">首页</a>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</div>

<!--登录内容 -->
<div class="account-container stacked">
    <div class="content clearfix">
        <form action="/admin/login.html" method="post">
            <h1>登录</h1>

            <div class="login-fields">
                <p>使用您的管理员账户登录:</p>

                <div class="field">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" value="" placeholder="用户名"
                           class="login username-field"/>
                </div>
                <!-- /field -->

                <div class="field">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" value="" placeholder="密码"
                           class="login password-field"/>
                </div>
            </div>

            <div class="login-actions">

				<span class="login-checkbox">
					<input id="Field" name="Field" type="checkbox" class="field login-checkbox" value="First Choice"
                           tabindex="4"/>
					<label class="choice" for="Field">记住我</label>
				</span>
                <button class="button btn btn-warning btn-large">登录</button>

            </div>
        </form>
    </div>
</div>
<script src="/resource/js/jquery-1.10.1.js"></script>
<script src="/resource/bootstrap/js/bootstrap.js"></script>
</body>
</html>
