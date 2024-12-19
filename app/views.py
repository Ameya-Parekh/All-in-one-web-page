from django.shortcuts import render,redirect,HttpResponseRedirect,HttpResponse
from . models import Customer
from . models import Product
from . models import Cart
from . models import OrderPlaced
from . forms import CustomerProfileForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.db.models import Q
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import PasswordChangeForm,PasswordResetForm, SetPasswordForm
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import update_session_auth_hash,get_user_model


def home(request):
    topwears=Product.objects.filter(category='TW')
    bottomwears=Product.objects.filter(category='BW')
    mobile=Product.objects.filter(category='M')
    return render(request,'app/home.html',{'topwear':topwears,'bottomwears':bottomwears,'mobile':mobile})

# @login_required
def product_detail(request,pk):
    product=Product.objects.get(pk=pk)
    item_already_in_cart = False
    if request.user.is_authenticated:
        item_already_in_cart = Cart.objects.filter(Q(product=product.id)&Q(user=request.user)).exists()
    return render(request, 'app/productdetail.html',{'product':product,'item_already_in_cart':item_already_in_cart})

@login_required
def Buy_Now(request):
 return render(request, 'app/buy.html')

@login_required
def cart(request):
    user=request.user
    product_id=request.GET.get('product_id')
    product=Product.objects.get(id=product_id)
    Cart(user=user,product=product).save()
    return redirect('/cart/')

@login_required
def show_cart(request):
   if request.user.is_authenticated:
      user = request.user
      cart=Cart.objects.filter(user=user)
      amount=0.0
      shipping_amount=70.0
      total_amount=0.0
      cart_product=[p for p in Cart.objects.all() if p.user == user]
      print(cart_product)
      if cart_product:
        for p in cart_product:
            tempamount=(p.quantity*p.product.discounted_price)
            amount+=tempamount
            totalamount=amount+shipping_amount
        
        return render(request, 'app/addtocart.html',{'carts':cart,'totalamount':totalamount,'amount':amount})
      else:
         return render(request,'app/emptycart.html')
   else:
      return render(request,'app/emptycart.html')

      
@login_required
def profile(request):
    form=CustomerProfileForm(request.POST)
    if form.is_valid():
        usr=request.user
        name=form.cleaned_data['name']
        locality=form.cleaned_data['locality']
        city=form.cleaned_data['city']
        state=form.cleaned_data['state']
        zipcode=form.cleaned_data['zipcode']
        reg=Customer(user=usr,name=name,locality=locality,city=city,state=state,zipcode=zipcode)
        reg.save()
        messages.success(request,"Congratulations Profile Updated Successfully!!")
        return redirect('/profile/')
    else:
        form=CustomerProfileForm()
        return render(request, 'app/profile.html',{'form':form}) 



@login_required
def address(request):
    list=Customer.objects.filter(user=request.user)
    return render(request, 'app/address.html',{'list':list})

@login_required
def orders(request):
    es=OrderPlaced.objects.filter(user=request.user)
    return render(request, 'app/orders.html',{'order':es})

@login_required
def change_password(request):
    data={}
    user = User.objects.get(id=request.user.id)

    if request.method=='POST':
      old_password=request.POST.get('old_password')
      new_password=request.POST.get('new_password')
      confirm_new_password=request.POST.get('confirm_new_password')

      if new_password==confirm_new_password:
        if user.check_password(old_password):
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request,'Password changed successfully')
            return redirect('/changepassword/')        
        else:
            data['error_msg']="Old Password Does Not Exits"
            return render(request, 'app/changepassword.html',data)
      else:
        data['error_msg']="Password Does Not Match"
        return render(request, 'app/changepassword.html',data)

    else:
      return render(request, 'app/changepassword.html',data)
    


         

def login_user(request):
    data={}
    if request.method=='POST':
        email=request.POST.get('Email')
        passw=request.POST.get('password')
        user=authenticate(request,username=email,password=passw)
        if user is not None:
            login(request,user)
            return redirect('/')
        else:
            data['error_msg']="Wrong Credentials"
            return render(request,'app/login.html',data)
    else:
        return render(request,'app/login.html')


def customerregistration(request):
    data={}
    if request.method=="POST":
        name=request.POST['name']
        username=request.POST['username']
        password=request.POST['password']
        password2=request.POST['password2']
        if (name=="" or username=="" or password=="" or password2==""):
            data['error_msg']="Fields can't be empty"
        elif(password!=password2):
            data['error_msg']="Password Does Not Matched"
        elif(User.objects.filter(username=username).exists()):
            data['error_msg']=username + " Already exist"
        else:
            user=User.objects.create(username=username,first_name=name)
            user.set_password(password)
            user.save()
            return redirect("/login")
    return render(request,'app/customerregistration.html',context=data)
@login_required
def logout_user(request):
  logout(request)
  return redirect('/')

@login_required
def checkout(request):
    user=request.user
    add=Customer.objects.filter(user=user)
    cart_items=Cart.objects.filter(user=user)
    amount=0.0
    shipping_amount=70
    totalamount=0.0
    cart_product=[p for p in Cart.objects.all() if p.user == request.user]
    if cart_product:
        for p in cart_product:
            tempamount=(p.quantity*p.product.discounted_price)
            amount+=tempamount
            totalamount=amount+shipping_amount
    return render(request, 'app/checkout.html',{'add':add,'display':cart_items,'totalamount':totalamount,'amount':amount})

@login_required
def checkoutProduct(request,id):
    user=request.user
    add=Customer.objects.filter(user=user)
    product=Product.objects.get(id=id)
    amount=0.0
    shipping_amount=70
    totalamount=0.0
    
    amount+=product.discounted_price
    totalamount=amount+shipping_amount

    return render(request, 'app/checkoutProduct.html',{'add':add,'display':product,'totalamount':totalamount})

@login_required
def plus_cart(request):
    if request.method == 'GET':
        prod_id = request.GET['prod_id']
        print(prod_id)
        c = Cart.objects.get(Q(product=prod_id) & Q(user=request.user))
        c.quantity+=1
        c.save()
        amount=0.0
        shipping_amount=70.0
        cart_product=[p for p in Cart.objects.all() if p.user == request.user]
        for p in cart_product:
            tempamount=(p.quantity*p.product.discounted_price)
            amount+=tempamount
        data={
           'quantity':c.quantity,
           'amount':amount,
           'totalamount':amount+shipping_amount
           }
        return JsonResponse(data)
@login_required
def minus_cart(request):
    if request.method == 'GET':
        prod_id = request.GET['prod_id']
        print(prod_id)
        c = Cart.objects.get(Q(product=prod_id) & Q(user=request.user))
        c.quantity-=1
        c.save()
        amount=0.0
        shipping_amount=70.0
        cart_product=[p for p in Cart.objects.all() if p.user == request.user]
        for p in cart_product:
            tempamount=(p.quantity*p.product.discounted_price)
            amount+=tempamount

        data={
           'quantity':c.quantity,
           'amount':amount,
           'totalamount':amount+shipping_amount
           }
        return JsonResponse(data)
@login_required   
def remove_cart(request,id):
    pi=Cart.objects.get(pk=id)
    pi.delete()
    return HttpResponseRedirect('/cart/')
# @login_required
def mobile_data(request,data=None):
    if data == None:
        mobiles=Product.objects.filter(category="M")
    elif data=="Redmi" or data=='Samsung' or data=='Iphone':
      mobiles=Product.objects.filter(category="M").filter(brand=data)
    elif data == "below":
      mobiles=Product.objects.filter(category="M").filter(discounted_price__lt=10000)
    elif data == "above":
      mobiles=Product.objects.filter(category="M").filter(discounted_price__gt=10000)
    return render(request,'app/mobile.html',{'mobile':mobiles})

@login_required
def payment_done(request):
	custid = request.GET.get('custid')
	print("Customer ID", custid)    
	user = request.user
	cartid = Cart.objects.filter(user = user)
	customer = Customer.objects.get(id=custid)
	print(customer)
	for cid in cartid:
		OrderPlaced(user=user, customer=customer, product=cid.product, quantity=cid.quantity).save()
		print("Order Saved")
		cid.delete()
		print("Cart Item Deleted")
	return redirect("orders")


@login_required
def paymentProduct_done(request,id):
    custid = request.GET.get('custid')
    print("Customer ID", custid)
    user = request.user
    customer_id = Customer.objects.get(id=custid)
    product_id = Product.objects.get(id=id)
    OrderPlaced(user=user, customer=customer_id, product=product_id).save()
    print("Order Saved")
    return redirect("orders")

UserModel = get_user_model()

def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = UserModel.objects.filter(username=data)
            print(associated_users)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "app/password_reset_email.html"
                    c = {
                        "email": user.username,
                        'domain': request.get_host(),
                        'site_name': 'all in One',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, settings.DEFAULT_FROM_EMAIL, [user.username], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect("/password_reset_done/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="app/password_reset.html", context={"password_reset_form":password_reset_form})

def password_reset_confirm(request, uidb64=None, token=None):
    if uidb64 is not None and token is not None:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = UserModel.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if request.method == 'POST':
                form = SetPasswordForm(user, request.POST)
                if form.is_valid():
                    form.save()
                    return redirect('/reset_password_complete/')
            else:
                form = SetPasswordForm(user)
            return render(request, 'app/password_reset_confirm.html', {'form': form})
        else:
            return render(request, 'app/password_reset_invalid.html')
    return redirect('/')

def password_reset_complete(request):
    return render(request, 'app/password_reset_complete.html')

def password_reset_done(request):
    return render(request, 'app/password_reset_done.html')
      
