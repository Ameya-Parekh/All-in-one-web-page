from django.contrib import admin
from . models import Customer
from . models import Product
from . models import Cart
from . models import OrderPlaced
# Register your models here.

# admin.site.register(Customer)

class CategoryAdmin(admin.ModelAdmin):
    list_display=['user','name','locality','city','zipcode','state']
admin.site.register(Customer,CategoryAdmin)

class ProductAdmin(admin.ModelAdmin):
    list_display=['title','selling_price','discounted_price','description','brand','category','product_image']
admin.site.register(Product,ProductAdmin)

class CartAdmin(admin.ModelAdmin):
    list_display=['user','product','quantity']
admin.site.register(Cart,CartAdmin)


class OrderAdmin(admin.ModelAdmin):
    list_display=['user','customer','product','quantity','ordered_date','status']
admin.site.register(OrderPlaced,OrderAdmin)


