/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CrlDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include "RevocationList.h"
#include "OpenDb.h"
#include "lib/pki_crl.h"
#include <QLabel>
#include <QTextEdit>
#include <QLineEdit>

CrlDetail::CrlDetail(MainWindow *mainwin)
	:QDialog(mainwin)
{
	mw = mainwin;
	setupUi(this);
	setWindowTitle(XCA_TITLE);

	image->setPixmap(*MainWindow::revImg);
	issuerSqlId = QVariant();
}

void CrlDetail::setCrl(pki_crl *crl)
{
	pki_x509 *iss;
	const char *mds;
	x509v3ext e1, e2;
	const EVP_MD *md;
	int salt, trailer;

	iss = crl->getIssuer();
	signCheck->disableToolTip();
	signCheck->setClickText(crl->getSigAlg());
	if (iss != NULL) {
		issuerIntName->setText(iss->getIntName());
		issuerIntName->setClickText(iss->getSqlItemId().toString());
		issuerIntName->setGreen();
		if (crl->verify(iss)) {
			signCheck->setText(crl->getSigAlg());
			signCheck->setGreen();
		} else {
			signCheck->setText(tr("Failed"));
			signCheck->setRed();
		}
		issuerSqlId = iss->getSqlItemId();
	} else {
		issuerIntName->setText(tr("Unknown signer"));
		issuerIntName->setDisabled(true);
		issuerIntName->disableToolTip();
		signCheck->setText(tr("Verification not possible"));
		signCheck->setDisabled(true);
	}

	if (crl->signed_with_pss()) {
		crl->pss_parameters(&md, &salt, &trailer);

		switch (EVP_MD_type(md)) {
		case NID_sha1:
			mds = "SHA1";
			break;
		case NID_sha256:
			mds = "SHA256";
			break;
		case NID_sha384:
			mds = "SHA384";
			break;
		case NID_sha512:
			mds = "SHA512";
			break;
		default:
			mds = "unknown";
			break;
		}

		pssparams->setVisible(true);
		pss_hashalgo->setText(QString(mds));
		pss_mgf1->setText(QString(mds));
		pss_saltlen->setText(QString("0x%1").arg(salt, 0, 16));
		pss_trailerfield->setText(QString("0x%1").arg(trailer, 0, 16));
	} else {
		pssparams->setVisible(false);
	}

	connect(signCheck, SIGNAL(doubleClicked(QString)),
		MainWindow::getResolver(), SLOT(searchOid(QString)));

	descr->setText(crl->getIntName());
	lUpdate->setText(crl->getLastUpdate().toPretty());
	lUpdate->setToolTip(crl->getLastUpdate().toPrettyGMT());
	nUpdate->setText(crl->getNextUpdate().toPretty());
	nUpdate->setToolTip(crl->getNextUpdate().toPrettyGMT());
	version->setText((++crl->getVersion()));

	issuer->setX509name(crl->getSubject());

	RevocationList::setupRevocationView(certList, crl->getRevList(), iss);

	v3extensions->document()->setHtml(crl->printV3ext());

	comment->setPlainText(crl->getComment());
}

void CrlDetail::itemChanged(pki_base *pki)
{
	if (pki->getSqlItemId() == issuerSqlId)
		issuerIntName->setText(pki->getIntName());
}
