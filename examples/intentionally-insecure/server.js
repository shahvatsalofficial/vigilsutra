// Intentionally insecure demo. Values are fake; nothing here is a live credential.
const { exec } = require("child_process");
const db_password = "hunter2-not-a-real-pass";
app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, () => res.send("ok"));
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  eval(req.body.expr);
});
