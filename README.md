# TODO APP

A simple TODO application built using Flask, designed to help users manage their tasks efficiently.

## Features
- Add, update, and delete tasks.
- Mark tasks as completed.
- View all tasks in a user-friendly interface.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/FlaskTry.git
   cd FlaskTry
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the database (if applicable):
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

## Usage

1. Run the Flask development server:
   ```bash
   flask run
   ```

2. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

3. Start managing your tasks!

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push the branch.
4. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Bootstrap](https://getbootstrap.com/) for UI components (if used).
