from . import db
from flask_login import UserMixin
from sqlalchemy import ForeignKey


class User(db.Model, UserMixin):
    __tablename__ = "app_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    security_question = db.Column(db.String(150), nullable=False)
    security_answer = db.Column(db.String(150), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'), nullable=False)
    priority = db.Column(db.Integer, default=1)
    parent_task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=True)
    depth = db.Column(db.Integer, default=0)  # Track nesting depth

    # Self-referential relationship for subtasks
    subtasks = db.relationship('Task',
                               backref=db.backref('parent_task', remote_side=[id]),
                               lazy='dynamic',
                               cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Task {self.title}>'

    @property
    def is_subtask(self):
        return self.parent_task_id is not None

    @property
    def subtask_count(self):
        return self.subtasks.count()

    @property
    def completed_subtask_count(self):
        return self.subtasks.filter_by(completed=True).count()

    @property
    def completion_percentage(self):
        if self.subtask_count == 0:
            return 100 if self.completed else 0
        return int((self.completed_subtask_count / self.subtask_count) * 100)

    @property
    def all_subtasks_recursive(self):
        """Get all subtasks recursively (including nested subtasks)"""
        subtasks = []
        for subtask in self.subtasks:
            subtasks.append(subtask)
            subtasks.extend(subtask.all_subtasks_recursive)
        return subtasks

    @property
    def total_subtask_count_recursive(self):
        """Get total count of all subtasks including nested ones"""
        return len(self.all_subtasks_recursive)

    @property
    def completed_subtask_count_recursive(self):
        """Get count of completed subtasks including nested ones"""
        return len([task for task in self.all_subtasks_recursive if task.completed])

    @property
    def completion_percentage_recursive(self):
        """Get completion percentage including all nested subtasks"""
        total = self.total_subtask_count_recursive
        if total == 0:
            return 100 if self.completed else 0
        completed = self.completed_subtask_count_recursive
        return int((completed / total) * 100)

    @property
    def root_task(self):
        """Get the root task (top-level task)"""
        if self.parent_task_id is None:
            return self
        return self.parent_task.root_task

    def get_ancestors(self):
        """Get list of ancestor tasks from root to immediate parent"""
        ancestors = []
        current = self.parent_task
        while current:
            ancestors.insert(0, current)  # Insert at beginning to maintain order
            current = current.parent_task
        return ancestors

    def update_depth(self):
        """Update the depth of this task based on its position in the hierarchy"""
        if self.parent_task_id is None:
            self.depth = 0
        else:
            self.depth = self.parent_task.depth + 1

        # Update depth for all subtasks recursively
        for subtask in self.subtasks:
            subtask.update_depth()

    # def can_add_subtask(self, max_depth=5):
    #     """Check if we can add a subtask (to prevent infinite nesting)"""
    #     return self.depth < max_depth

    # Add this method to your Task model class
    def can_add_subtask(self, max_depth):
        """Check if a subtask can be added without exceeding max depth"""
        return self.depth < max_depth - 1