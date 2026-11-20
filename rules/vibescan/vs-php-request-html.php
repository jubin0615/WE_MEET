<?php
// ruleid: vs-php-request-html
echo $_GET["text"];
// ok: vs-php-request-html
echo htmlspecialchars($_GET["text"], ENT_QUOTES, "UTF-8");
// ok: vs-php-request-html
echo $labels["text"];
