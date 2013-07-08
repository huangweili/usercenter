<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Bootstrap</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">
    <link href="/resource/bootstrap/css/bootstrap.css?v=1" rel="stylesheet"/>
    <link href="/resource/bootstrap/css/bootstrap-responsive.css?v=1" rel="stylesheet"/>
    <link href="/resource/ztree/css/zTreeStyle/zTreeStyle.css?v=1" rel="stylesheet"/>
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
                        <a href="#" class="">用户信息</a>
                    </li>
                    <li class="">
                        <a href="#" class="">退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</div>

<div class="container">
    <div class="container-fluid">
        <div class="row-fluid">
            <div class="span3">
                <div class="well sidebar-nav ">
                    <ul class="additional-menu">
                        <li>
                            <a href="#">LDAP树形列表</a>
                        </li>
                    </ul>
                    <ul id="ldaptree" class="ztree"></ul>
                </div>
            </div>
            <div class="span9">

                <div class="hero-unit">
                    <h1>Hello, world!</h1>

                    <p>This is a template for a simple marketing or informational website. It includes a large callout
                        called the hero unit and three supporting pieces of content. Use it as a starting point to
                        create something more unique.</p>

                    <p><a href="#" class="btn btn-primary btn-large">Learn more &raquo;</a></p>
                </div>
                <div class="row-fluid">
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                </div>
                <!--/row-->
                <div class="row-fluid">
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                    <div class="span4">
                        <h2>Heading</h2>

                        <p>Donec id elit non mi porta gravida at eget metus. Fusce dapibus, tellus ac cursus commodo,
                            tortor mauris condimentum nibh, ut fermentum massa justo sit amet risus. Etiam porta sem
                            malesuada magna mollis euismod. Donec sed odio dui. </p>

                        <p><a class="btn" href="#">View details &raquo;</a></p>
                    </div>
                    <!--/span-->
                </div>
                <!--/row-->
            </div>
            <!--/span-->
        </div>
    </div>
</div>


<script src="/resource/js/jquery-1.10.1.js?v=1"></script>
<script src="/resource/bootstrap/js/bootstrap.js?v=1"></script>
<script src="/resource/ztree/js/jquery.ztree.all-3.5.js?v=1"></script>

<script type="text/javascript">
    var setting = {    };

    var zNodes = [
        { name: "dc=hwlcn,dc=com", open: true,
            children: [
                { name: "OU=NPBOK", open: true,
                    children: [
                        { name: "CN=ldapadmin"}
                    ]},
                { name: "CN=Users", open: true,
                    children: [
                        { name: "CN=Administrators"},
                        { name: "CN=Guest"},
                        { name: "CN=MOSS"},
                        { name: "CN+netsys"}
                    ]},
            ]
        }
    ];

    $(document).ready(function () {
        $.fn.zTree.init($("#ldaptree"), setting, zNodes);
    });

</script>

</body>
</html>
