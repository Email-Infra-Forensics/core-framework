"""
evaluate_dataset.py — Evaluación masiva de Falsos Positivos y Falsos Negativos (Fase 2/3).

Este script lee el dataset completo (out.jsonl), evalúa cada muestra con el motor ETI,
y compara el resultado con la etiqueta real (label) para obtener métricas de precisión.
"""

import json
from pathlib import Path
from collections import defaultdict
import argparse

from eti_core.scoring.eti import calculate_eti
from eti_core.msgid.signature import OrgSignature
from eti_core.models import EmailHeaders, Hop, HopClassification, AuthResult, AuthStatus

def _convert_hop(h_data: dict) -> Hop:
    # Mapear strings a enum HopClassification
    c = h_data.get("classification", "unknown")
    cls = HopClassification.UNKNOWN
    if c == "known_esp": cls = HopClassification.KNOWN_ESP
    elif c == "transit": cls = HopClassification.TRANSIT
    elif c == "anomalous": cls = HopClassification.ANOMALOUS
    
    return Hop(
        index=h_data.get("index", 0),
        raw=h_data.get("raw", ""),
        from_host=h_data.get("from_host"),
        by_host=h_data.get("by_host"),
        with_protocol=h_data.get("with_protocol"),
        ip=h_data.get("ip"),
        timestamp=h_data.get("timestamp"),
        asn=h_data.get("asn"),
        asn_org=h_data.get("asn_org"),
        classification=cls
    )

def _convert_auth(a_data: str) -> AuthResult:
    if not a_data:
        return AuthResult(raw=None, dkim=AuthStatus.NONE, spf=AuthStatus.NONE, dmarc=AuthStatus.NONE)
    
    a_data_lower = a_data.lower()
    return AuthResult(
        raw=a_data,
        dkim=AuthStatus.PASS if "dkim=pass" in a_data_lower else AuthStatus.FAIL if "dkim=fail" in a_data_lower else AuthStatus.NONE,
        spf=AuthStatus.PASS if "spf=pass" in a_data_lower else AuthStatus.FAIL if "spf=fail" in a_data_lower else AuthStatus.NONE,
        dmarc=AuthStatus.PASS if "dmarc=pass" in a_data_lower else AuthStatus.FAIL if "dmarc=fail" in a_data_lower else AuthStatus.NONE,
    )

def main():
    parser = argparse.ArgumentParser(description="Evaluar ETI contra Ground Truth")
    parser.add_argument("--dataset", default="/home/luval/Escritorio/Email-Trust/data-curator/data/out.jsonl", help="Ruta a out.jsonl")
    parser.add_argument("--baselines", default="/home/luval/Escritorio/Email-Trust/core-framework/data/baselines", help="Directorio de firmas .json")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    baselines_dir = Path(args.baselines)
    
    if not dataset_path.exists():
        print(f"Error: No se encontró el dataset en {dataset_path}")
        return
        
    print(f"Cargando firmas desde {baselines_dir}...")
    signatures = {}
    if baselines_dir.exists():
        for sig_file in baselines_dir.glob("*_signature.json"):
            try:
                org_name = sig_file.name.replace("_signature.json", "")
                signatures[org_name] = OrgSignature.load(sig_file)
            except Exception as e:
                print(f"Error cargando {sig_file}: {e}")
                
    print(f"Firmas cargadas: {len(signatures)}")

    stats = {
        "total": 0,
        "processed": 0,
        "true_positives": 0,  # Legítimo etiquetado como Trusted
        "false_positives": 0, # Legítimo etiquetado como Anomalous/Suspicious
        "true_negatives": 0,  # Phishing etiquetado como Anomalous/Suspicious
        "false_negatives": 0, # Phishing etiquetado como Trusted
        "unknown_labels": 0
    }
    
    fp_details = []
    fn_details = []

    print(f"\nEvaluando dataset: {dataset_path.name}...")
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                stats["total"] += 1
                
                label = data.get("label")
                if not label or label == "unknown":
                    if data.get("source_dataset") == "local":
                        label = "legitimate"
                    else:
                        label = "phishing"  # kaggle or enron (assuming enron/kaggle phishing sets)
                        
                if label not in ["legitimate", "phishing"]:
                    stats["unknown_labels"] += 1
                    continue
                    
                from eti_core.scoring.characterization import get_org_for_domain, EXPLICIT_GROUPS

                sender_domain = data.get("sender_domain") or ""
                sender_domain_lower = sender_domain.lower() if sender_domain else ""
                
                # Inferencia precisa de organización
                org_name = get_org_for_domain(sender_domain_lower) if sender_domain_lower else None
                sender_in_db = False
                org_sig = None

                if org_name and org_name in signatures:
                    org_sig = signatures[org_name]
                    sender_in_db = True
                elif org_name and org_name in EXPLICIT_GROUPS:
                    sender_in_db = True
                
                headers = EmailHeaders(
                    message_id=data.get("message_id_raw"),
                    from_address=data.get("from_address", "") or "unknown",
                    to_address=data.get("to_address", "") or "unknown",
                    hops=[_convert_hop(h) for h in data.get("received_hops", [])],
                    auth=_convert_auth(data.get("authentication_results_raw")),
                    sender_domain=sender_domain or None
                )
                
                # Calcular ETI
                score = calculate_eti(headers, org_signature=org_sig, sender_in_db=sender_in_db)
                
                # Comparar con ground truth
                eti_label = score.label  # "trusted", "suspicious", "anomalous"
                
                if label == "legitimate":
                    if eti_label == "trusted":
                        stats["true_positives"] += 1
                    else:
                        stats["false_positives"] += 1
                        fp_details.append({
                            "domain": sender_domain,
                            "score": score.eti,
                            "eti_label": eti_label,
                            "reasons": score.breakdown.reasons
                        })
                elif label == "phishing":
                    if eti_label in ["suspicious", "anomalous"]:
                        stats["true_negatives"] += 1
                    else:
                        stats["false_negatives"] += 1
                        fn_details.append({
                            "domain": sender_domain,
                            "score": score.eti,
                            "eti_label": eti_label,
                            "reasons": score.breakdown.reasons
                        })
                        
                stats["processed"] += 1
            except Exception as e:
                import traceback
                print(f"Error procesando línea: {e}")
                traceback.print_exc()
                break

    print("\n" + "="*50)
    print(" RESULTADOS DE EVALUACIÓN (Fase 2/3)")
    print("="*50)
    print(f"Total en dataset: {stats['total']}")
    print(f"Total procesados (con label conocido): {stats['processed']}")
    print("-" * 50)
    print(f"True Positives (Legítimos detectados correctamente): {stats['true_positives']}")
    print(f"False Positives (Legítimos bloqueados por ETI): {stats['false_positives']}")
    print(f"True Negatives (Phishing bloqueado por ETI): {stats['true_negatives']}")
    print(f"False Negatives (Phishing EVADIÓ el filtro ETI): {stats['false_negatives']}")
    print("-" * 50)
    
    if stats['processed'] > 0:
        accuracy = (stats['true_positives'] + stats['true_negatives']) / stats['processed'] * 100
        print(f"Exactitud General (Accuracy): {accuracy:.2f}%")
        
        if (stats['true_positives'] + stats['false_negatives']) > 0:
            fn_rate = stats['false_negatives'] / (stats['true_positives'] + stats['false_negatives']) * 100
            print(f"Tasa de Falsos Negativos (Evasión): {fn_rate:.2f}%")
            
        if (stats['true_negatives'] + stats['false_positives']) > 0:
            fp_rate = stats['false_positives'] / (stats['true_negatives'] + stats['false_positives']) * 100
            print(f"Tasa de Falsos Positivos (Bloqueo erróneo): {fp_rate:.2f}%")
    
    print("\n" + "="*50)
    print(" ANÁLISIS RECOMENDADO PARA AJUSTE DE PESOS (weights.yaml)")
    print("="*50)
    if stats['false_negatives'] > 0:
        print(f"⚠️  Existen {stats['false_negatives']} correos Phishing etiquetados como Trusted.")
        print("   -> Considera aumentar el umbral 'trusted' o aumentar el peso de la firma MSG-ID.")
        
    if stats['false_positives'] > 0:
        print(f"⚠️  Existen {stats['false_positives']} correos Legítimos penalizados.")
        print("   -> Considera disminuir las penalizaciones por ASN desconocidos o bajar el umbral 'trusted'.")
        print("\nEjemplos de razones (primeros 5):")
        for i, fp in enumerate(fp_details[:5]):
            print(f"  - {fp['domain']} (Score: {fp['score']}): {', '.join(fp['reasons'])}")

if __name__ == "__main__":
    main()
