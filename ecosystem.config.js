module.exports = {
  apps: [
    {
      name: "TODO-app",
      script: ".venv/bin/python",
      args: "run.py",
      cwd: "/Users/Ashish/Downloads/Python_Project/FlaskTry",
      interpreter: "none",
      env: {
        FLASK_ENV: "production",
        PYTHONUNBUFFERED: "1"
      }
    }
  ]
};
