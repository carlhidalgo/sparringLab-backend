# users/management/commands/delete_user_by_email.py
from django.core.management.base import BaseCommand
from supabase import create_client
import os

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

class Command(BaseCommand):
    help = 'Deletes a user from Supabase Auth by email'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='Email of the user to delete')

    def handle(self, *args, **kwargs):
        email = kwargs['email']

        try:
            users = supabase.auth.admin.list_users()
            user = next((u for u in users.data if u.email == email), None)

            if user:
                supabase.auth.admin.delete_user(user.id)
                self.stdout.write(self.style.SUCCESS(f'Successfully deleted user: {email}'))
            else:
                self.stdout.write(self.style.WARNING(f'User not found: {email}'))

        except Exception as e:
            self.stderr.write(f'Error deleting user: {str(e)}')
