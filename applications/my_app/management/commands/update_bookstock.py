

from django.db import transaction
from applications.my_app.models import Book
from django.core.management.base import BaseCommand



    
class Command(BaseCommand):
    help = "add stock to books"

    @transaction.atomic
    def handle(self, *args, **options):
        try:
            # Example logic to update book stock
            objs = Book.objects.bulk_update(
                [
                    Book(id=1, in_stock=10),
                    Book(id=2, in_stock=25),
                    Book(id=3, in_stock=40),
                    Book(id=4, in_stock=20),
                ],
                fields=["in_stock"] 
            )
            
        except Exception as e:
            print(f"Error updating book stock: {e}")
            raise
        
        self.stdout.write(
            self.style.SUCCESS('Book stock updated successfully.')
        )