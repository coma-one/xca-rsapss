/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include <typeinfo>

#include "pki_x509.h"
#include "pki_evp.h"
#include "func.h"
#include "db_base.h"
#include "x509name.h"
#include "exception.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <QDir>

#include "openssl_compat.h"

QPixmap *pki_x509req::icon[3] = { NULL, NULL, NULL };

pki_x509req::pki_x509req(const QString name)
	: pki_x509super(name)
{
	request = X509_REQ_new();
	pki_openssl_error();
	pkiType=x509_req;
	done = false;
	resetX509count();
}

pki_x509req::~pki_x509req()
{
	if (request)
		X509_REQ_free(request);
}

QSqlError pki_x509req::insertSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_x509super::insertSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "INSERT INTO requests (item, hash, signed, request) "
		  "VALUES (?, ?, ?, ?)");
	q.bindValue(0, sqlItemId);
	q.bindValue(1, hash());
	q.bindValue(2, done ? 1 : 0);
	q.bindValue(3, i2d_b64());
	q.exec();
	return q.lastError();
}

void pki_x509req::markSigned(bool signe)
{
	XSqlQuery q;
	Transaction;
	TransThrow();

	SQL_PREPARE(q, "UPDATE requests SET signed=? WHERE item=?");
	q.bindValue(0, signe ? 1 : 0);
	q.bindValue(1, sqlItemId);
	q.exec();

	if (q.lastError().isValid())
		return;
	done = signe;
	AffectedItems(sqlItemId);
	TransCommit();
}

void pki_x509req::restoreSql(const QSqlRecord &rec)
{
	pki_x509super::restoreSql(rec);
	QByteArray ba = QByteArray::fromBase64(
				rec.value(VIEW_x509req_request).toByteArray());
	d2i(ba);
	done = rec.value(VIEW_x509req_signed).toBool();
}

QSqlError pki_x509req::deleteSqlData()
{
	XSqlQuery q;
	QSqlError e = pki_x509super::deleteSqlData();
	if (e.isValid())
		return e;
	SQL_PREPARE(q, "DELETE FROM requests WHERE item=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	return q.lastError();
}

void pki_x509req::createReq(pki_key *key, const x509name &dn, const EVP_MD *md, extList el, int pss)
{
	int result;
	EVP_MD_CTX *ctx;
	EVP_PKEY *privkey;
	EVP_PKEY_CTX *pkctx;
	QList<int> bad_nids; bad_nids << NID_authority_key_identifier <<
		NID_issuer_alt_name << NID_undef;

	result = 0;

	if (key->isPubKey()) {
		my_error(tr("Signing key not valid (public key)"));
		return;
	}

	X509_REQ_set_version(request, 0L);
	X509_REQ_set_pubkey(request, key->getPubKey());
	setSubject(dn);
	pki_openssl_error();

	foreach(int nid , bad_nids)
		el.delByNid(nid);

	el.delInvalid();

	if (el.count() > 0) {
		STACK_OF(X509_EXTENSION) *sk;
		sk = el.getStack();
		X509_REQ_add_extensions(request, sk);
		sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	}
	pki_openssl_error();

	privkey = key->decryptKey();
	pki_openssl_error();

	prepare_signing_context(&ctx, &pkctx, md, privkey, pss);

	if (X509_REQ_sign_ctx(request, ctx) == 0)
		result = 0;
	else
		result = 1;

	EVP_MD_CTX_free(ctx);

	if (result == 0) {
		pki_openssl_error();
		// In case pki_openssl_error() didn't end up throwing..
		my_error("x509req::sign failed");
	}
}

QString pki_x509req::getMsg(msg_type msg) const
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 * The drawback are all the slightly different duplicated messages
	 *
	 * %1 will be replaced by either "SPKAC" or "PKCS#10"
	 * %2 will be replaced by the internal name of the request
	 */

	QString type = "PKCS#10";

	switch (msg) {
	case msg_import: return tr("Successfully imported the %1 certificate request '%2'").arg(type);
	case msg_delete: return tr("Delete the %1 certificate request '%2'?").arg(type);
	case msg_create: return tr("Successfully created the %1 certificate request '%2'").arg(type);
	/* %1: Number of requests; %2: list of request names */
	case msg_delete_multi: return tr("Delete the %1 certificate requests: %2?");
	}
	return pki_base::getMsg(msg);
}

void pki_x509req::fromPEM_BIO(BIO *bio, QString name)
{
	X509_REQ *req;
	req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
	openssl_error(name);
	X509_REQ_free(request);
	request = req;
}

void pki_x509req::fload(const QString fname)
{
	X509_REQ *_req;
	int ret = 0;
	XFile file(fname);
	file.open_read();
	_req = PEM_read_X509_REQ(file.fp(), NULL, NULL, NULL);
	if (!_req) {
		pki_ign_openssl_error();
		file.retry_read();
		_req = d2i_X509_REQ_fp(file.fp(), NULL);
	}
	if (ret || pki_ign_openssl_error()) {
		if (_req)
			X509_REQ_free(_req);
		throw errorEx(tr("Unable to load the certificate request in file %1. Tried PEM, DER and SPKAC format.").arg(fname));
	}

	if (_req) {
		X509_REQ_free(request);
		request = _req;
	}
	autoIntName();
	if (getIntName().isEmpty())
		setIntName(rmslashdot(fname));
	pki_openssl_error();
}

void pki_x509req::d2i(QByteArray &ba)
{
	X509_REQ *r= (X509_REQ*)d2i_bytearray(D2I_VOID(d2i_X509_REQ), ba);
	if (r) {
		X509_REQ_free(request);
		request = r;
	}
}

QByteArray pki_x509req::i2d() const
{
	return i2d_bytearray(I2D_VOID(i2d_X509_REQ), request);
}

void pki_x509req::fromData(const unsigned char *p, db_header_t *head )
{
	int size;

	size = head->len - sizeof(db_header_t);
	QByteArray ba((const char *)p, size);

	d2i(ba);
	pki_openssl_error();

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

void pki_x509req::addAttribute(int nid, QString content)
{
	if (content.isEmpty())
		return;

	ASN1_STRING *a = QStringToAsn1(content, nid);
	X509_REQ_add1_attr_by_NID(request, nid, a->type, a->data, a->length);
	ASN1_STRING_free(a);
	openssl_error(QString("'%1' (%2)").arg(content).arg(OBJ_nid2ln(nid)));
}

x509name pki_x509req::getSubject() const
{
	x509name x(X509_REQ_get_subject_name(request));
	pki_openssl_error();
	return x;
}

int pki_x509req::sigAlg() const
{
	return X509_REQ_get_signature_nid(request);
}

RSA_PSS_PARAMS *
pki_x509req::internal_pss_parameters(void)
{
	RSA_PSS_PARAMS *pss;
	const struct X509_algor_st *sigalgo;

	if (!signed_with_pss())
		my_error("get_pss_parameters called on non PSS signed request");

	X509_REQ_get0_signature(request, NULL, &sigalgo);

	pss = (RSA_PSS_PARAMS *)ASN1_TYPE_unpack_sequence(
	    ASN1_ITEM_rptr(RSA_PSS_PARAMS), sigalgo->parameter);
	pki_openssl_error();

	return (pss);
}

void pki_x509req::setSubject(const x509name &n)
{
	X509_REQ_set_subject_name(request, n.get());
}

void pki_x509req::writeDefault(const QString &dirname) const
{
	XFile file(get_dump_filename(dirname, ".csr"));
	file.open_write();
	writeReq(file, true);
}

void pki_x509req::writeReq(XFile &file, bool pem) const
{
	if (!request)
		return;
	if (pem) {
		PEM_file_comment(file);
		PEM_write_X509_REQ(file.fp(), request);
	} else {
		i2d_X509_REQ_fp(file.fp(), request);
	}
	pki_openssl_error();
}

BIO *pki_x509req::pem(BIO *b, int format)
{
	(void)format;
	if (!b)
		b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(b, request);
	return b;
}

int pki_x509req::verify() const
{
	EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	bool x = X509_REQ_verify(request,pkey) > 0;
	pki_ign_openssl_error();
	EVP_PKEY_free(pkey);
	return x;
}

pki_key *pki_x509req::getPubKey() const
{
	 EVP_PKEY *pkey = X509_REQ_get_pubkey(request);
	 pki_ign_openssl_error();
	 if (pkey == NULL)
		 return NULL;
	 pki_evp *key = new pki_evp(pkey);
	 pki_openssl_error();
	 return key;
}

extList pki_x509req::getV3ext() const
{
	extList el;
	STACK_OF(X509_EXTENSION) *sk;
	sk = X509_REQ_get_extensions(request);
	el.setStack(sk);
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	return el;
}

QString pki_x509req::getAttribute(int nid) const
{
	int n;
	int count;
	QStringList ret;

	n = X509_REQ_get_attr_by_NID(request, nid, -1);
	if (n == -1)
		return QString("");
	X509_ATTRIBUTE *att = X509_REQ_get_attr(request, n);
	if (!att)
		return QString("");
	count = X509_ATTRIBUTE_count(att);
	for (int j = 0; j < count; j++)
		ret << asn1ToQString(X509_ATTRIBUTE_get0_type(att, j)->
				             value.asn1_string);
	return ret.join(", ");
}

int pki_x509req::issuedCerts() const
{
	XSqlQuery q;
	int count = 0;

	if (x509count != -1)
		return x509count;

	SQL_PREPARE(q, "SELECT item FROM x509super WHERE key_hash=?");
	q.bindValue(0, pubHash());
	q.exec();
	if (q.lastError().isValid())
		return 0;
	pki_key *k = getPubKey();
	if (!k)
		return 0;
	while (q.next()) {
		pki_x509super *x;
		x = db_base::lookupPki<pki_x509super>(q.value(0));
		if (!x) {
			qDebug("x509 with id %d not found",
				q.value(0).toInt());
			continue;
		}
		if (typeid(*x) == typeid(pki_x509) && x->compareRefKey(k))
			count++;
		qDebug() << "Req:" << getIntName() << "Cert with hash"
			 << x->getIntName() << count;
	}
	delete k;
	x509count = count;
	return count;
}

QVariant pki_x509req::column_data(const dbheader *hd) const
{
	switch (hd->id) {
	case HD_req_signed:
		return QVariant(done ? tr("Signed") : tr("Unhandled"));
	case HD_req_unstr_name:
		return getAttribute(NID_pkcs9_unstructuredName);
	case HD_req_chall_pass:
		return getAttribute(NID_pkcs9_challengePassword);
	case HD_req_certs:
		return QVariant(issuedCerts());
	}
	return pki_x509super::column_data(hd);
}

QVariant pki_x509req::getIcon(const dbheader *hd) const
{
	int pixnum = -1;

	switch (hd->id) {
	case HD_internal_name:
		pixnum = hasPrivKey() ? 0 : 1;
		break;
	case HD_req_signed:
		if (done)
			pixnum = 2;
		break;
	default:
		return pki_x509super::getIcon(hd);
	}
	if (pixnum == -1)
		return QVariant();
	return QVariant(*icon[pixnum]);
}

bool pki_x509req::visible() const
{
	if (pki_x509super::visible())
		return true;
	if (getAttribute(NID_pkcs9_unstructuredName).contains(limitPattern))
		return true;
	if (getAttribute(NID_pkcs9_challengePassword).contains(limitPattern))
		return true;
	return false;
}
