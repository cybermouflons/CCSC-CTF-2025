// register enterKey event
(function($) {
	$.fn.catchEnter = function(sel) {
		return this.each(function() {
			$(this).on('keyup', sel, function(e) {
				if (e.keyCode == 13)
					$(this).trigger("enterkey");
			})
		});
	};
})(jQuery);

let isLogin = true;

$(document).ready(function() {
	// set input events
	$("#login-btn").on('click', action);
	$("#register-btn").on('click', action);
	$("#username").catchEnter().on('enterkey', action);
	$("#password").catchEnter().on('enterkey', action);
	$("#to-login-btn").on('click', toggleView);
	$("#to-register-btn").on('click', toggleView);
});

function toggleView() {
	isLogin = !isLogin;
	$('.islogin').toggle();
	$('.isregister').toggle();
}

function toggleInputs(state) {
	$("#username").prop("disabled", state);
	$("#password").prop("disabled", state);
	$("#login-btn").prop("disabled", state);
	$("#register-btn").prop("disabled", state);
}

function showMessage(msg, type='warning') {
	let card = $("#alert-msg");
	card.text(msg);
	card.attr("class", "alert alert-" + type + " mt-3");
	card.show();
}

async function action() {

	toggleInputs(true); // disable inputs

	// prepare alert
	let card = $("#alert-msg");
	card.attr("class", "alert alert-info mt-3");
	card.hide();

	// validate
	let user = $("#username").val();
	let pass = $("#password").val();
	if ($.trim(user) === '' || $.trim(pass) === '') {
		toggleInputs(false);
		showMessage("Please input username and password first!");
		return;
	}

	if (isLogin) {
		await fetch('/api/login', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					'auth.username' : user,
					'auth.password' : pass,
				}),
			})
			.then((response) => response.json()
				.then((resp) => {
					if (response.status == 200) {
						showMessage(resp.message, type='success');
						window.location.href = '/panel';
						return;
					}
					showMessage(resp.message);
				}))
			.catch((error) => {
				showMessage(error);
			});
	}
	else {
		await fetch('/api/register', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					'user.username' : user,
					'user.password' : pass,
				}),
			})
			.then((response) => response.json()
				.then((resp) => {
					if (response.status == 200) {
						$("#password").val('');
						showMessage(resp.message, type='success');
						toggleView();
						return;
					}
					showMessage(resp.message);
				}))
			.catch((error) => {
				showMessage(error);
			});
	}

	toggleInputs(false);
}