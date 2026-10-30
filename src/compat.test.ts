import { describe, expect, it } from 'vitest';
import { getSodium } from './sodium.js';
import { decryptFile } from './envelope.js';
import { decryptJson, fingerprintPublicKeys, openPrivateKeys } from './client-keys.js';
import { importRecoveryFile, type RecoveryFile } from './recovery.js';
import type { RecipientPrivateKeys, RecipientPublicKeys } from './types.js';

/**
 * Vecteurs figés de compatibilité : fichiers produits une fois par la version 2 du format (X-Wing), puis
 * committés. Ils garantissent que ce que lexdocia-collect a chiffré reste lisible par PieceMaster, quelles que
 * soient les mises à jour de libsodium ou de @noble/post-quantum.
 *
 * Ces clés sont des clés de TEST (graine 01 02 … 20), générées uniquement pour ces vecteurs : elles ne protègent
 * aucune donnée réelle. Ne JAMAIS régénérer ces vecteurs pour faire passer un test rouge : un échec ici signifie
 * qu'un fichier déjà chiffré en production ne serait plus lisible. Un changement de format doit passer par un
 * nouveau FORMAT_VERSION et garder ces vecteurs de la version précédente.
 *
 * (Les vecteurs de la version 1, hybride X25519 + ML-KEM-768 combiné par BLAKE2b, ont été retirés : toutes
 * les données v1 ont été remises à zéro lors de la migration vers X-Wing, aucun fichier v1 n'existe plus.)
 */
const VECTEURS = {
  "publicKey": "Mus18dBaBNnLThGQX1nAoSBEbduqIHhovizMAZa2F8VFljEMttBuTHRs1cGr0CEMIRDD8cyHQWMRvFE5jES9hgvBOGQUVJSHedQs6AQT3gEXYiE8sfNdvaAfeqatqxQqUblHc7wz5ZRRrWcmadoVQfVg2wcV0XkCgtvGQHOFxLuUfCZrOuWIViKbQdbJh8lo78w8CdEjv4G7HPFRJFx7Kwc7BIibAozNECUMElFzJYqtQ-B8wSDK4np_ECLGTzoPz1eMycOOW1qetJsWUquC3YcAaOsApluJ6tnJ0PuEoaEGVrWyHvGKYls4Lxt-VgCx1YjJlOg3qUkypRtxlIc-LYZ2QnNkLFmuXvfDILMlg9xuW5kEc0RhVVUmF3GZC7G3PDOAtWEVnGiZvpN8KGk7qNe9YxAGRvzIdqKCt-SYzje0OJxzgmdEq8G2Pvg_5lctPcg_q7bG7ETFkxquRrk-1uGL_pg-RsALIduy0hnDUjeEDaxOWVB5_vOFyHfINWMkrpVsL8dTQpxbaud8QSyYZ4xoCfVdzydNZFZf0wh0lRykGoAT-chqgdgTJyFWflFChbEQ2LdhpKIfFLgKaRVOCrsTijeM43ymFecXeDSCyWkKPBgMdLoNBfFWvqS5bmU0swEaHzw7VFImYauC8ElRauCVfwG5x4JzhkYxamSrb5hYjMUgSOlxU9TOhJdu_qjFvyVXkyjFr3pPdqy-3nAktXXDCkht6hMBMfsyUNw9EtZKfICzxpAdiSZwf7ma59ZGNXA9niOUC8F0mIfIB5sdyXGn7yN_87SyiOd4nquSZFBb1MRchnwPtPS1FoA7znBe3fJQFPcsPGGm_6phETMAq8goTDB4VtpolGnEp4NGv_wI0Pdd17UxzPFJ27mZkIeemLdDVSiSJxxQD-NE4oOIlZGoSgkAcLUVOCgTD_oerNKPuQIkiItL56Bxb5ghc_gN7YxyoWo7B-iH6NAzJ7y_fncznFFPKbRLZtB9mHi3bzyp9ZqwPEx2AcG_mIE7Y9MwwCbEb9nFcdo4MrBIqUSEy8cJaBg7XodkFOm7RdU91GWbXUpm3UVBryqkoksqnoKZB2opO8tNhpWSxFBJTwM01JBthJSfaFxACxKPNYfK-KGoUla3brLNRlkIqMOa11ZVKbVEN4UUwhsNsJrL_VyHHNmg2hQGPQNeB4gQ6cas2HfF0jQVKNo_TEWyijZQ7gh42jU060CdC9gQg6QeEqt6BfuGjSTB0EiyODx4AQsJVLRigqlXMBqtiZfLZSdHE-jOBlMTnDIWS3HOb7K-KOxwklQgqqPMaMKoXrksRFOAw1vF5WbPH9fPcOetXkhSIjSoTQhIBxJm4_kucyMT42d_sDQKR2R0T8d_v7BYKGc1UYlRnEdw-Js6wpNJZKx7LAXENZh-0kO9FOID7BBZ3tJKPLwEtGTAfVtjFYJGHRpGAZy933IIB0IM95ondOImyjc-ChKDqMSSa9WkVrlXJOMi5yoHOxiUSzkta3adi8tgWLMe6aZKz9CtGRymhpVIyXEFerVg4BasXIMFhxCW3Ri5B3jCzhTtdnHHpn1EGTLZymGRg1oZdcGhlE1sfszL5zubX6kBpSgJD_rd6XIFS2opOg",
  "privateKey": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
  "fichier": {
    "ciphertext": "Arsz-cwG5a9U3jVsiY8FHRaVRM45xX-yROyP7QfbjN0b64jWURcVGazJJ3e4DEDZo_IEYmLBbT0E6h5FHh-bpCCrhIsN96K1svgRhRsSCy-WjTzLRcqyuFVM2Q",
    "encapsulatedKey": "AjFIXvvB5HukszUMzmQJAas3VPz9dBsxNamI7kJCiGQa6e6pfHo9VFZ3dY6N0qvppYYB9V9RqmmOnorLDUSrFwMqPN3ddt5wpiP-kdUNI7rUEj9NyjGbeAgCGHTLFf71xTpz3XET2jPe9n2DftLrKEPS3ks4tSttkpBIUbkNji7VL5jVQ37CV0JlOAuL9A49OBA8Y08CAlCzQe2_H3uaChzxBmIxAN-Za2eTRhPRdVAXd0kZzvROsSFhdtk_Vi02_jPgneop22TSpyV_6tr8gHghmKtrGOSyPYdp_1O3E12Ewl_6SKcLLnG58yACsylFgy4dygRwFy2eYCVs00RePP8Fxtl9Whx2xwQuOMF4LYBCnjVGcEgtOCIx70PUvZbLbkc3-TlgHowaG8GZpvH5c9LdgvF6JPC63nxUsfrm1y19xsPkbq0Yvc430E8dNH1MLjMjRHJgwUGNu09VVlbK032xxsPGfghf6apzzGR8l76KMEEz9yEhraa0NYrHGNZDmdwOQ1kR-F22NCrH8RySCS43kNzP1Ppumg2gF-plS_8KhNpWpPTTT_CQs4T2lT8UC7thvwNrbm7qPP-dIWf3Szk5bY9OvU--pdSYFyNfaTt3iTDGtBedmIPU1biki3lsBuGbw73aTxkGhpxEpAma1cns7x17cYs76f4i3NSxjtQuulbsVAqLwqQ9dvLMgRZUgZ9r5Nm_pOhuiOQrThUUvJyigKofVFzItkPcYfM1NEVchlvY0_ZdHpfFANjNtuR3P_2p9UufJJqVxvcEGoD-mHTloIssqPPBOEBEJfsk85TGTOhTfssWap4o2skudoMROgQLpLbGjII77p4DP0yqM6zFM8BxSX3IMRqgIO1srvYnhl4yQxjps_24_FXZCA6G8mTNfzoqPiVx09rR87FCG4Qoo3tf-DT8TMZQuzHctxR1GnutDujafpWUDxsRKw1IQHUAANWOTFt1BhkWXp4MWzydLcO20M7cOQ_ChKsR8zVtV_Xcfw-h9ueYvR2ke4I7mIgbvJXEVubtEbdCNauwkPZ5kz97rDBkj60uQrx5dzRhr04EhhWka2y6leXZxZoui-ddN8ibbry8U75VBJnox0uuqNlCuhJFRUy8JhLAnsdziTrTxOOTtkSiQORB-k7sJPkjGcnjRfqr1qe6x8ojAtIXPGX-U8Tq69E4GmjrLazVRk6rcSeCp7G5s_C-OdF-NTeW2iIu9_T9lSVFT5LXPgdj3Ym0o4DUjSr-Z2PNbhVRWNABUvCOxN1zQ0qp_4V-An9q4rVNLdyKAhKThmUshlX2ntk_jspceKQqL5f0rPl3DS_5d87KZqs32olFE7H-xSMlQNDqb6Zav18v6XQjn3nuEA0Y_-hlhId8V1Y16JeFAky4EKqN06Wce1ev7ajj4DQaXgblSNzQewb-jTPZXclTJAHRgOf4bUSA7A_gY2pG6MQxLE5Tk6pAGCdrvD3O-qQL2J8Cl6-iHj0gR7pgS2h3bx0z53AWyG-v2BjFFGhxraXrI2DTR8ASaWjzVM3Ko0NCvTEY_ykg6S9wueRakRS2YjDrTHKcp7Q_NDu1w-IG4Zj4HthHbHY"
  },
  "fichierVide": {
    "ciphertext": "AuqY1cpZft7ee5_FK-BUnErxyovvcLYe1VyMOA73dTQvyV-ULG0z76Q",
    "encapsulatedKey": "Av-NwkDktRSYnZ6uX5kKc4Z9yGt9xpP4JPaA4fr0Sarj2isdVbRMg_Qz9TSpVo_oOJsD2-r_3fRqaCaChpGaic8GLmjh5AT4vUq83YFBF7_wJSiObtElUlJDVHVVIIrsQl-68tLXIOEEsJb124bN0OMLWOyxUNsyGR-D2QeXmZg3WAouBMbCgjVGeKBSU4sBLIvm0pLLnAJhxBkzuqAWzsgDgJvA9zJ8PHlUJokpvA9xWV2eTwOfB8y_4Imljj06erTQXENN49zswyXA3pa6BJY58Pkbds1VXPooL2NKIHk1IA0N-BZoWSFT9gScNKGyo0ykesgQP--CShEbYmAYy_nU8W0v8c4txV0V0S3BvGow7WP7Zlb7LnnNFFt0ZqcdX5V9BtMVU3vR_M4gMIW42_zJmjdifH9uyJHDz2YDhOJZOsDHC9dpRkOW_kbt6NdmYuVINwIMkzmHmFHf0-9m5YjyohWnXuWtagwajcBGPXcup019yS7IROuzwM3j7mFcwFyRTLFTyfEkYLaQ55HpqyHamy0iETJztHH9f2POmqsBVxyJmXigELO1xz78ohdGjG_zgwevlebzG1xFHq-SzUq4LlB2PfarYcvZvqCSF_bSQ0-VJZxbu0DWROkHUXTzWQCBtORJW0NNHix_eEFVwV-gKAPjo8LrshGr7R6TBSkW93aY-6JvU2Ur9Dd5mwAj6XvDUJQNZrzxz23JveXyxfennp01u_pTpTLR6uO-hJ2FPMtsi5Tq0hefEAou2MbSJEIGJb-6pzOENZzsFWoYK8oiAXKY6wGFEqHTMGrblnxiQlO6GDGo1fNsDmZoiiXWPYZlDqhn3LFhzLlKKaviQd5xaV0WMGaHwihvso-yLqFeVcdEGGrZP_NYirauDVFmYdVPdEO7i9RlVo9LQn2A81aiRvp5Q2QYNVj2FZAvfQ0UeTM8GalHfvIpAUcd6C-wW2N_8UNR8hjQSrxWcDC3m8yERyJ0Y-38kl8sEgE2No-6CTTABnggZFpW5PKCZdKVpcFRZ5aGgv8iDk98DEo2EyO2EpUib8nDxxcKhsA_bwCXgH-2oJUQNUO3D1CiEGeK4AYVlfnrjCZiJStrKSKXP95WQFt1qvgzVTCqGxfbTJtB3TSvCL8zcb3THY8MS8bOzgnA46W4ucWW80wd8wcvAArb7_MnjP5b6UpmbfV215NlLtISTue26j6HY99cK1XfDKicB28W8u_L97rdqKVI9RuPfe4OzKd-QmeBWxULOXHSt7Oc7LN8GdMm3H-_oF0KbHp05MWfQkfnxST702XsS0_NukqB1D2wF0ThWVpUFYjw-PPb9wh1kltbS0eBAsv_nznds6FBRj3ItL230d-z3eIspZhfSc2ePyDce1z4ogamQVcEsXSX_O961s_PjZGwhJ7vt9imHjd5iH0K0CtU2OXF2C445eFWg9ELmzlniYK0TeVctv6f8CV7hTteEpsBRFHezFu1sO7L5UFEj5hh2hmlO8geVNiONlHArrQY-8pYwu0ETkvtnr3Tv5GCAjJayu21-RMx4YSvWvJ9-m35BUidtNdF5BfEQkZS7TkutKmcdAwbKnq7c78"
  },
  "json": {
    "ciphertext": "ArjLJ00KAvQyupDSW9LLrQtVTj9GDcGMqIAc4jm6r5lCnMD4gSli4L4g2Er8T4xZVYW_H2e-qDART-qZ_73WflFNYll-jylSzHKtdNNuB7VFZqTGdNAB3lerBfdsoYS6_yjf",
    "encapsulatedKey": "AhPPykSUprpDzE_IvpXUYzVyn5I-WRoFheycOQdhkaYvnP8K2DEmsfmqnmQcJGi7kWlAZDrHiw_eU_dz7qxGWIokyVvzrxTGXNCL-RaC_77kk_BzkS1FqhdYJZBiWWOEkKkl4BmlRGD8xL8dEn-Zk_QJNOpO7LAzQbsS5iJcimy7KzaVTmNO-yjewXPEa8cJtY7Zmx9Nk2OXysmiAoLX62qwY0QdAkrnOfcwUjHHbCZ86Ekpo_gjh5l4ul29CEcB5wXI9yy9Z81_pn2iMMmNel7v51MxJ35EimzAkUOdxNdpogKbnLz_9Uttn5NYN1dozR8hAiqeL2rEb4FeuPoG0LT8z6m_jUIOTV79BWP-CdIeHUg-G7M5TN52coE0jF5QwSil9JFekbxvtCR9R_BqbK0BDQDPLjsqY3Kj5cJyjiyrrQhfVat35VKjldBLps1mown_PhT_HojYMdNreIEjfxpYjpS0JM4nQMxPWLOSoXPOYlO_PujYGYXUJsPwpUAWGw0DbvFtiPSRakCcumAUdAnXTPBvEukNhZc90f3vlHLPHG2CRNEAcvGzc7FUoMu3dCwTlDk3DtNt6hYzd32uIzjWOcRFBRLJIrPphxrrRnJsUnSNW_U6Hjx5f9Ar76_5aXV70b-vc9atid_4uGsMeUBdwWoi1byvwQbpprSavaVrLgZ3nuYHiMzBK5UtvPG9_ivnFqSSBvz4L01PdPQHIMo3xdJY10SfydBj2IholL259c7jowHu_yIw7SGCJue8mMAj3OcHbyNxzmcqT8yYvmnjIcHK7PSq_2MIdvf869_cziTC0SgC52Zu3Amd8HVS9aABl3ssULJz-Fsp-afE27zyoXl_EA7dKj4O-QAMnUt6YCYCNWo15RwzxsHUP00pVtfQntnBaizGz0ynOvVFTGUAHlg3Yjv6ycsl0slSfEmnB_b99fK-Z-8X79PlcEAcHIs0LR5vg4hOXlT_CmIdLRl_vteYjOT2ZesPqf_MDReEKAiMrNHxeQfoeS62I_LfRTHKfQQGMtHh17P2d_ucE6SzIqIOIz6A2D7yjNj4jCVG8I2XLuoPIkxddBtSIg3tf-H3xNqkGm_zRVTSbN62NSmnWGXpKcDGCXDFd-Kp-0KyjQvOHxhrM6-KY9q3EgKIrC0Hb1HY2hCzHQrM4Ag52MT1fxTc2USLWEnALnVDnKksHa5eFxt5pgZR1cV9qRYHfw9VJdPK66PgXYiKajvg0tOjWaP-I5RF65RoOHY7BD6zp8yr7N7VDHCk4AdB677K6IwUMQ7IgC7hHPs5rbMzLjBQsPVPK9KsUIUqwBmfDaBKvWUO2yl4D9yyK6TQoZvHOUUq8fTNQ4OPJh_MMSMo5AzVYuf3EDbKUSMofIC3bM5Z06zftx-og5aE63vPv0d-1pRCN0VrvXaFCuOSTGbMRMk4ypAU2X-aYNUySUKICbeL1SrELOwgnccyMCp9G4Bl1fVpezlDV0VzjWXq6M1VKVfxdrfl1BBQSVy9Tb3PzWKyMaE_OJxTik0y6B151y5_NMm1uvQE1Hsc4uREiQz29y_asTmyDKusKTcQqZeGgV4UijjEV0qem2M"
  },
  "recovery": {
    "version": 2,
    "kdf": {
      "algo": "argon2id",
      "salt": "9MZKHTAoZFF2aHo9pvZISQ",
      "opslimit": 1,
      "memlimit": 8192
    },
    "nonce": "0nBgFvBUhhYY5mtSPZ7fsdwA2LrkL5lo",
    "ciphertext": "ei9emkozAOt2v_2c9v43yXKKogjQbOc_xHYH5gfEXT9otLM9c1xldFTWkqxQHXhE"
  },
  "scelle": "Agjr-bIc9lbRmbF1Wj9gvGSJKZqewssTcAbbnhWAcpyKAX6bHDhZd6Uw4bp4crDTJqODQtiSRsE-y9G8_lrWKgIALal0u0AhDg",
  "empreinte": "18b7 d2d0 9550 4ae5 9784 40ba eabf b51a"
};

const decode = async (valeur: string): Promise<Uint8Array> => (await getSodium()).from_base64(valeur);

async function paquet(v: { ciphertext: string; encapsulatedKey: string }) {
  return { ciphertext: await decode(v.ciphertext), encapsulatedKey: await decode(v.encapsulatedKey) };
}

async function clesPrivees(): Promise<RecipientPrivateKeys> {
  return { privateKey: await decode(VECTEURS.privateKey) };
}

async function clesPubliques(): Promise<RecipientPublicKeys> {
  return { publicKey: await decode(VECTEURS.publicKey) };
}

describe('vecteurs figés de compatibilité (format v2)', () => {
  it('déchiffre le fichier chiffré par la version 2', async () => {
    const clair = await decryptFile(await paquet(VECTEURS.fichier), await clesPrivees());
    expect(new TextDecoder().decode(clair)).toBe('Pièce jointe confidentielle — dossier n°42 ✓');
  });

  it('déchiffre le fichier vide chiffré par la version 2', async () => {
    const clair = await decryptFile(await paquet(VECTEURS.fichierVide), await clesPrivees());
    expect(clair).toEqual(new Uint8Array(0));
  });

  it('déchiffre les métadonnées JSON chiffrées par la version 2', async () => {
    const meta = await decryptJson(await paquet(VECTEURS.json), await clesPrivees());
    expect(meta).toEqual({ nom: 'Contrat de bail.pdf', mimeType: 'application/pdf' });
  });

  it('relit le fichier de recovery exporté par la version 2', async () => {
    const cles = await importRecoveryFile(VECTEURS.recovery as RecoveryFile, 'mot-de-passe-de-test');
    expect(cles.privateKey).toEqual((await clesPrivees()).privateKey);
  });

  it('ouvre les clés privées scellées par la version 2 avec le secret de passkey', async () => {
    const cles = await openPrivateKeys(await decode(VECTEURS.scelle), new Uint8Array(32).fill(7));
    expect(cles.privateKey).toEqual((await clesPrivees()).privateKey);
  });

  it("calcule la même empreinte de clé publique qu'à l'origine", async () => {
    expect(await fingerprintPublicKeys(await clesPubliques())).toBe(VECTEURS.empreinte);
  });
});
