

from django.db import transaction
from applications.my_app.models import Book, Author, Publisher, Category

from django.core.management.base import BaseCommand



    
class Command(BaseCommand):
    help = "add first web data"

    @transaction.atomic
    def handle(self, *args, **options):
        try:
            authors_to_create = [
                Author(
                    name=f'Author {i}',
                    email=f"author{i}@gmail.com"

                )
                for i in range(1,5)
            ]

            # Bulk insert them into the database
            new_author = Author.objects.bulk_create(
                authors_to_create,
                ignore_conflicts=True
            )
            print (new_author)
            
            publishers_to_create = [
                Publisher(
                    name=f'Publisher {i}',
                    address=f'Address {i}'
                )
                for i in range(1, 5)
            ]
            
            # Bulk insert them into the database
            new_publisher = Publisher.objects.bulk_create(
                publishers_to_create,
                ignore_conflicts=True
            )
            
            print (new_publisher)
            
            categories_to_create = [
                Category( name=f'Horror' ),
                Category( name=f'Romance' ),
                Category( name=f'Thriller' ),
                Category( name=f'Fantasy' )
            ]
            # Bulk insert them into the database
            new_category = Category.objects.bulk_create(
                categories_to_create,
                ignore_conflicts=True
            )
            print (new_category)
                
        except Exception as e:
            print(f"Error adding products: {e}")
            raise
        
        self.stdout.write(
            self.style.SUCCESS('Product data added successfully.')
        )