from flask import Flask, render_template, request
from hash_utils import hash_string, verify_bcrypt
from lookup import dictionary_attack, lookup_hash

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/generate", methods=["POST"])
def generate():
    text = request.form.get("text")
    algorithm = request.form.get("algorithm")

    if not text or not algorithm:
        return render_template("index.html", error="Missing input!")

    try:
        hashed = hash_string(text, algorithm)
        return render_template("index.html", result=hashed, input=text, algorithm=algorithm, action="generate")
    except Exception as e:
        return render_template("index.html", error=str(e))


@app.route("/verify_bcrypt", methods=["POST"])
def verify():
    plain = request.form.get("plain")
    hashed = request.form.get("hashed")

    if not plain or not hashed:
        return render_template("index.html", error="Missing input!")

    result = verify_bcrypt(plain, hashed)
    message = "✅ Password matches bcrypt hash!" if result else "❌ Password does NOT match."
    return render_template("index.html", verify_result=message, action="verify")


@app.route("/lookup", methods=["POST"])
def lookup():
    hash_value = request.form.get("hash_value")
    algorithm = request.form.get("lookup_algorithm")

    if not hash_value or not algorithm:
        return render_template("index.html", error="Missing input!")

    # Try API lookup first
    result = lookup_hash(hash_value)
    if result:
        return render_template("index.html", lookup_result=f"✅ Found plaintext via API: {result}", action="lookup")

    # Fallback dictionary attack
    result = dictionary_attack(hash_value, algorithm)
    if result:
        return render_template("index.html", lookup_result=f"✅ Found plaintext via dictionary attack: {result}", action="lookup")
    else:
        return render_template("index.html", lookup_result="❌ Plaintext not found.", action="lookup")


if __name__ == "__main__":
    app.run(debug=True)
