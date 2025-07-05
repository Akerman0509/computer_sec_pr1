

from django.db import transaction
from applications.my_app.models import Customer, Cart

from django.core.management.base import BaseCommand



    
class Command(BaseCommand):
    help = "add customer data"

    @transaction.atomic
    def handle(self, *args, **options):
        try:
            customer_names = [
                    'Customer 1', 'Customer 2', 'Customer 3',
                    'Customer 4'
                ]
                # Step 1: Efficiently create all missing customers.
                # The returned objects here will NOT have IDs.
            Customer.objects.bulk_create(
                [Customer(name=name) for name in customer_names],
                ignore_conflicts=True
            )
            print(f"Bulk insert for customers attempted for names: {customer_names}")

            # Step 2: Re-fetch the customers from the database.
            # Now they will have their primary keys.
            customers_with_ids = Customer.objects.filter(name__in=customer_names)

            # Step 3: Create carts for each customer.
            for customer in customers_with_ids:
                # This is a small improvement: create and set the name in one go.
                # This avoids the redundant .save() call.
                new_cart, created = Cart.objects.get_or_create(
                    customer=customer,
                    defaults={'name': f"Cart of {customer.name}"}
                )
                if created:
                    print(f"Created a new cart for {customer.name}")

                print("Operation complete.")
                
        except Exception as e:
            print(f"Error adding customers: {e}")
            raise
        
        self.stdout.write(
            self.style.SUCCESS('Customer data added successfully.')
        )