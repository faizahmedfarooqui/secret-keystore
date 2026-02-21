# Push to your new GitHub repo (faizahmedfarooqui/secret-keystore)

Run these in order from the project root.

---

## Step 1: Create the first commit with your author info

Stage everything, then commit with your name/email (so only you show as contributor):

```bash
cd /Users/faizahmedfarooqui/Sites/products/secret-keystore

git add -A
git commit -m "Initial commit" --author="Faiz Ahmed Farooqui <faizahmedfarooqui@users.noreply.github.com>"
```

Verify:

```bash
git log -1 --format='%an <%ae>'
```

You should see: Faiz Ahmed Farooqui and your email.

---

## Step 2: Point remote at the new repo

If you already have a remote named `personal`, update its URL:

```bash
git remote set-url personal https://github.com/faizahmedfarooqui/secret-keystore.git
```

If you don’t have `personal` yet:

```bash
git remote add personal https://github.com/faizahmedfarooqui/secret-keystore.git
```

Check:

```bash
git remote -v
```

`personal` should show `https://github.com/faizahmedfarooqui/secret-keystore.git` (or the SSH URL if you use SSH).

---

## Step 3: Push (logged in as faizahmedfarooqui)

Use the account **faizahmedfarooqui** when Git asks for credentials.

```bash
git push -u personal main
```

Done. The new repo will have one commit and you as the only contributor.
